/**
 * Learning Rooms — Batch 33
 *
 * Closes the #1 highest-impact gap flagged in the 2026-08 expert review
 * (docs/LEARNING-ROOMS-EXPERT-REVIEW-2026-08.md): ransomware is the single
 * most frequent real-world SOC incident type, and the platform had zero
 * dedicated room walking the full lifecycle end to end. Every prior
 * ransomware-adjacent room (SentinelOne, CrowdStrike, memory forensics,
 * malware types) teaches one stage or one detection in isolation. This room
 * follows one intrusion — NexaCorp, 14 April 2026 — from a phished helpdesk
 * technician through credential theft, discovery, lateral movement, defense
 * evasion, the 2025 exfiltration-first double-extortion model, and finally
 * fleet-wide encryption, teaching what a SOC analyst actually does at every
 * single stage, not just at the moment the ransom note appears.
 *
 * Room in this batch:
 *  1. ransomware-full-lifecycle — RaaS/double-extortion economics, initial
 *     access (phishing T1566, edge-device exploitation T1190, RDP brute
 *     force T1110/T1021.001), execution/persistence (LOLBins, scheduled
 *     tasks, run keys), discovery/credential access (AD recon, LSASS T1003.001,
 *     DCSync T1003.006), lateral movement (PsExec T1021.002, WMI, RDP),
 *     defense evasion (shadow-copy deletion T1490, disabling EDR T1562.001,
 *     clearing logs T1070.001), the exfiltration-first double-extortion model
 *     (T1567.002), impact (T1486) and the full-chain containment playbook.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Ransomware: Full Attack Lifecycle
// ===========================================================================

const lsassMiniDumpEvent: TelemetryEvent = {
  id: "evt-rw-la1-001",
  ts: "2026-04-14T02:47:18.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_access",
  severity: "critical",
  hostname: "WKS-IT-0417",
  user_email: "j.reyes@nexacorp.com",
  user_title: "IT Support Technician",
  mitre_technique: "T1003.001",
  mitre_tactic: "Credential Access",
  description:
    "Falcon flagged a process reaching into lsass.exe's memory on an IT support workstation. Three days earlier, this same technician reported a suspicious calendar-invite email attached to a helpdesk ticket, and today's activity begins at 02:47 AM.",
  process: {
    name: "rundll32.exe",
    pid: 7744,
    path: "C:\\Windows\\System32\\rundll32.exe",
    parent_name: "cmd.exe",
    parent_pid: 5502,
    cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 C:\\ProgramData\\Adobe\\ARM\\wer4A21.tmp full",
    user: "NEXACORP\\j.reyes",
    hash: {
      sha256: "a3f8c2e19b4d6f70c1e5a2948d3b6f02e7a1c9d45f8b2e603a9d7c146e2f8b05",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessAccess",
    "crowdstrike.DetectId": "ldt:3c7f9a1e5d2b4c608f1a3e5b7c9d2f04:41207",
    "crowdstrike.IncidentId": "inc:3c7f9a1e5d2b4c608f1a3e5b7c9d2f04:20260414",
    "crowdstrike.SeverityName": "Critical",
    "crowdstrike.Tactic": "Credential Access",
    "crowdstrike.Technique": "OS Credential Dumping",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "cmd.exe",
    "crowdstrike.ParentProcessName": "cmd.exe",
    "crowdstrike.FileName": "rundll32.exe",
    "crowdstrike.FilePath": "C:\\Windows\\System32\\rundll32.exe",
    "crowdstrike.CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 C:\\ProgramData\\Adobe\\ARM\\wer4A21.tmp full",
    "crowdstrike.SHA256HashData": "a3f8c2e19b4d6f70c1e5a2948d3b6f02e7a1c9d45f8b2e603a9d7c146e2f8b05",
    "crowdstrike.TargetProcessName": "lsass.exe",
    "crowdstrike.TargetProcessId": "668",
    "crowdstrike.GrantedAccess": "0x1FFFFF",
    "crowdstrike.CallStackModuleNames": "comsvcs.dll,ntdll.dll,KERNELBASE.dll",
    "crowdstrike.UserName": "NEXACORP\\j.reyes",
    "crowdstrike.HostName": "WKS-IT-0417",
    "event.action": "process-access",
    "event.outcome": "success",
  },
};

const rcloneExfilEvent: TelemetryEvent = {
  id: "evt-rw-la2-001",
  ts: "2026-04-14T04:58:42.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "high",
  hostname: "SRV-FILES-04",
  user_email: "j.reyes@nexacorp.com",
  user_title: "IT Support Technician",
  mitre_technique: "T1567.002",
  mitre_tactic: "Exfiltration",
  it_verify_result: "unverified",
  it_verify_message:
    "No change ticket found authorizing a data transfer from SRV-FILES-04 tonight. The file server's only documented backup tool is the nightly Veeam Agent job, which runs under svc-veeam-backup and writes to the on-premises backup appliance, not to any cloud remote.",
  description:
    "A file-transfer utility ran on the Finance file server two hours after the credential-access finding on WKS-IT-0417, using the account that workstation's cached token belonged to.",
  process: {
    name: "rclone.exe",
    pid: 3312,
    path: "C:\\Users\\Public\\rclone.exe",
    parent_name: "cmd.exe",
    parent_pid: 6108,
    cmdline: "rclone.exe copy \\\\SRV-FILES-04\\Shared\\Finance Q4 gdrive-sync:archive --config C:\\Users\\Public\\rc.conf -q --transfers 16",
    user: "NEXACORP\\j.reyes",
    hash: {
      sha256: "7c4a9e2f1d8b6035f2a9c7e46b3d8f10a5e1c9420f7b3d689c2a5e174d8f0b63",
    },
  },
  network: {
    domain: "gdrive-sync-relay.net",
    bytes_out: 91_483_200_000,
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.DetectId": "ldt:8b2e4f6a1c9d3e507b4a2c8f1d6e9b30:52918",
    "crowdstrike.IncidentId": "inc:8b2e4f6a1c9d3e507b4a2c8f1d6e9b30:20260414",
    "crowdstrike.SeverityName": "High",
    "crowdstrike.Tactic": "Exfiltration",
    "crowdstrike.Technique": "Exfiltration to Cloud Storage",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "cmd.exe",
    "crowdstrike.ParentProcessName": "cmd.exe",
    "crowdstrike.FileName": "rclone.exe",
    "crowdstrike.FilePath": "C:\\Users\\Public\\rclone.exe",
    "crowdstrike.CommandLine": "rclone.exe copy \\\\SRV-FILES-04\\Shared\\Finance Q4 gdrive-sync:archive --config C:\\Users\\Public\\rc.conf -q --transfers 16",
    "crowdstrike.SHA256HashData": "7c4a9e2f1d8b6035f2a9c7e46b3d8f10a5e1c9420f7b3d689c2a5e174d8f0b63",
    "crowdstrike.UserName": "NEXACORP\\j.reyes",
    "crowdstrike.HostName": "SRV-FILES-04",
    "event.action": "process-create",
    "event.outcome": "success",
  },
};

const migrationRcloneEvent: TelemetryEvent = {
  id: "evt-rw-ac1-001",
  ts: "2026-03-02T23:10:00.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "high",
  hostname: "SRV-ARCHIVE-02",
  user_email: "svc-migrate@nexacorp.com",
  mitre_technique: "T1567.002",
  mitre_tactic: "Exfiltration",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-40881 authorizes the FY25 records-migration project moving SRV-ARCHIVE-02's legacy project archive to the company's licensed SharePoint tenant. svc-migrate is the documented service account for the migration vendor's scripted nightly uploads, scheduled to run until the project completes.",
  description:
    "Falcon fired a High-severity Exfiltration-to-Cloud-Storage detection on an archive server. The technique pattern matches the same family flagged earlier this room on SRV-FILES-04.",
  process: {
    name: "rclone.exe",
    pid: 4410,
    path: "C:\\Program Files\\RecordsMigration\\rclone.exe",
    parent_name: "MigrationScheduler.exe",
    parent_pid: 2201,
    cmdline: "rclone.exe copy D:\\Archive\\Legacy-Projects sharepoint-nexacorp:RecordsMigration\\Legacy --config C:\\ProgramData\\RecordsMigration\\rclone.conf --transfers 8 --log-file C:\\ProgramData\\RecordsMigration\\logs\\run-0302.log",
    user: "NEXACORP\\svc-migrate",
    hash: {
      sha256: "2f6a9c1e4b8d3f705a2c9e1b6d4f8a30c7e2b5d9a1f4c6087b3e9d2a5c1f6b48",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.DetectId": "ldt:5e9a2c7f1b4d6e803a5c9f2e7b1d4a60:33104",
    "crowdstrike.IncidentId": "inc:5e9a2c7f1b4d6e803a5c9f2e7b1d4a60:20260302",
    "crowdstrike.SeverityName": "High",
    "crowdstrike.Tactic": "Exfiltration",
    "crowdstrike.Technique": "Exfiltration to Cloud Storage",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "MigrationScheduler.exe",
    "crowdstrike.ParentProcessName": "MigrationScheduler.exe",
    "crowdstrike.FileName": "rclone.exe",
    "crowdstrike.FilePath": "C:\\Program Files\\RecordsMigration\\rclone.exe",
    "crowdstrike.CommandLine": "rclone.exe copy D:\\Archive\\Legacy-Projects sharepoint-nexacorp:RecordsMigration\\Legacy --config C:\\ProgramData\\RecordsMigration\\rclone.conf --transfers 8 --log-file C:\\ProgramData\\RecordsMigration\\logs\\run-0302.log",
    "crowdstrike.SHA256HashData": "2f6a9c1e4b8d3f705a2c9e1b6d4f8a30c7e2b5d9a1f4c6087b3e9d2a5c1f6b48",
    "crowdstrike.UserName": "NEXACORP\\svc-migrate",
    "crowdstrike.HostName": "SRV-ARCHIVE-02",
    "event.action": "process-create",
    "event.outcome": "success",
  },
};

const encryptorImpactEvent: TelemetryEvent = {
  id: "evt-rw-la3-001",
  ts: "2026-04-14T07:12:05.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "critical",
  hostname: "WKS-HR-0233",
  user_email: "j.reyes@nexacorp.com",
  mitre_technique: "T1486",
  mitre_tactic: "Impact",
  description:
    "In the last five minutes, Falcon has fired sixty-one near-identical Critical detections across the fleet. This is one of them.",
  process: {
    name: "wuauclt32.exe",
    pid: 9184,
    path: "C:\\Windows\\Temp\\wuauclt32.exe",
    parent_name: "svchost.exe",
    parent_pid: 1188,
    cmdline: "wuauclt32.exe --path C:\\ --ext .a8f2e91c --note RESTORE-FILES-a8f2e91c.txt --skip C:\\Windows,C:\\ProgramData,C:\\$Recycle.Bin --threads 24",
    user: "NT AUTHORITY\\SYSTEM",
    integrity: "system",
    hash: {
      sha256: "b6f2a9d43e7c1b850a4d9f268c3e5b71d29a4f607b1e8c354f9d2a63e0b7c891",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.DetectId": "ldt:1f5a8c3e7b2d4f609e1c3a5b7d9f2e60:67350",
    "crowdstrike.IncidentId": "inc:1f5a8c3e7b2d4f609e1c3a5b7d9f2e60:20260414",
    "crowdstrike.SeverityName": "Critical",
    "crowdstrike.Tactic": "Impact",
    "crowdstrike.Technique": "Data Encrypted for Impact",
    "crowdstrike.PatternDispositionDescription": "Detected, kill process",
    "crowdstrike.ContextProcessName": "svchost.exe",
    "crowdstrike.ParentProcessName": "svchost.exe",
    "crowdstrike.FileName": "wuauclt32.exe",
    "crowdstrike.FilePath": "C:\\Windows\\Temp\\wuauclt32.exe",
    "crowdstrike.CommandLine": "wuauclt32.exe --path C:\\ --ext .a8f2e91c --note RESTORE-FILES-a8f2e91c.txt --skip C:\\Windows,C:\\ProgramData,C:\\$Recycle.Bin --threads 24",
    "crowdstrike.SHA256HashData": "b6f2a9d43e7c1b850a4d9f268c3e5b71d29a4f607b1e8c354f9d2a63e0b7c891",
    "crowdstrike.UserName": "NT AUTHORITY\\SYSTEM",
    "crowdstrike.HostName": "WKS-HR-0233",
    "event.action": "process-create",
    "event.outcome": "success",
  },
};

const ransomwareLifecycleRoom = {
  id: "ransomware-full-lifecycle",
  title: "Ransomware: Full Attack Lifecycle — From Initial Access to Extortion",
  description:
    "Follow one ransomware intrusion end to end: how the affiliate gets in (phishing, edge-device exploitation, RDP brute force), what they do once inside (execution, persistence, AD discovery, LSASS/DCSync credential access, PsExec/WMI/RDP lateral movement, shadow-copy deletion, disabling EDR, clearing logs), the 2025 exfiltration-first double-extortion model that moves stolen data out before a single file is encrypted, and finally fleet-wide encryption and the extortion note — with the specific detection point and containment action a SOC analyst owns at every single stage, not just at the moment the ransom note appears.",
  difficulty: "advanced" as const,
  category: "Incident Response",
  estimatedMinutes: 105,
  xp: 620,
  icon: "🔒",
  prerequisites: ["active-directory", "endpoint-security-fundamentals", "persistence-mechanisms"],
  tasks: [
    // ── Reading 1: RaaS economics & double extortion ─────────────────────────
    {
      type: "reading" as const,
      id: "rw-r1",
      heading: "Ransomware Is an Industry, Not a Program",
      content:
        "Every other room on this platform teaches ransomware as a single moment — the encryption event itself. In the real world, encryption is the last few minutes of an intrusion that can run for days or weeks before a single file gets touched. This room walks the entire chain: how the affiliate gets in, what they do once they're inside, how they steal data before they ever encrypt anything, and what a SOC analyst is actually supposed to do at every individual stage.\n\n" +
        "**The Ransomware-as-a-Service (RaaS) model.** Most large-scale ransomware today is not one gang doing everything themselves. A RaaS operator builds and maintains the encryptor, the negotiation portal, and the leak site, then rents that whole toolkit to independent affiliates who carry out the actual intrusion — the phishing, the credential theft, the lateral movement — and split the ransom proceeds with the operator, commonly weighted heavily toward the affiliate, though the exact split varies group to group and shifts over time. This means a ransomware family name is a brand for a rented toolkit, not a single, consistent group of people behind the keyboard — two intrusions using the same encryptor can have completely different initial access methods, tempo, and even native language, because they were run by two different affiliates.\n\n" +
        "**Initial Access Brokers (IABs).** A further specialization exists one layer upstream: criminals who do nothing but break into networks — via phishing, credential stuffing, or exploiting exposed services — and then sell that already-compromised foothold on a criminal marketplace to whichever ransomware affiliate is buying. The person who broke in and the person who eventually deploys the encryptor are frequently not the same person, or even part of the same group, which is part of why dwell time (the gap between initial access and the final impact stage) can be so unpredictable.\n\n" +
        "**Why double extortion exists.** Encryption alone used to be the entire attack: lock the files, demand payment for the key. Once organizations got serious about offline and immutable backups, that leverage collapsed — a victim with a clean, tested backup can simply restore and ignore the ransom note entirely. Starting around 2019-2020, ransomware operators responded by adding a second, independent form of leverage: steal a copy of the victim's sensitive data before encrypting anything, and threaten to publish it on a dedicated leak site regardless of whether the victim restores from backup or not. This is double extortion, and it is why a strong backup strategy — while still essential — stopped being sufficient on its own to guarantee an organization walks away from a ransomware incident unscathed.\n\n" +
        "**Why this framing matters before anything else in this room.** If the goal is only to stop 'the encryption,' the SOC is defending against the last five minutes of a much longer intrusion. Every stage between initial access and impact — discovery, credential theft, lateral movement, defense evasion, and especially the exfiltration-staging window covered later in this room — is a chance to stop the intrusion before the leverage the attacker is counting on ever actually leaves the building, or before a single file gets touched at all.",
      diagram:
        "flowchart LR\n" +
        "  IAB[\"Initial Access Broker sells a foothold\"] --> AFF[\"RaaS affiliate buys access, runs the intrusion\"]\n" +
        "  OP[\"RaaS operator supplies the encryptor + leak site + negotiation portal\"] --> AFF\n" +
        "  AFF --> RANSOM[\"Ransom paid (if any)\"]\n" +
        "  RANSOM -->|majority share| AFF\n" +
        "  RANSOM -->|remaining share| OP\n",
      diagramCaption: "The specialized, multi-party ransomware economy behind one intrusion",
      checkpoint: {
        question: "Per Reading 1, why did ransomware operators add data exfiltration and leak-site threats (double extortion) on top of encryption?",
        options: [
          "Because encryption alone had become technically impossible to perform reliably on modern Windows systems",
          "Because stronger offline and immutable backups meant a victim could often just restore and ignore an encryption-only ransom demand, so a second, independent form of leverage was needed",
          "Because law enforcement banned ransom payments for encryption-only incidents in most countries, forcing a workaround",
          "Because leak sites are required by ransomware insurance providers before any claim can be processed",
        ],
        answer: 1,
        explanation:
          "Reading 1 was explicit: once good backups made 'just restore and ignore the note' a viable option for encryption-only attacks, operators needed leverage that survived even a clean restore -- stolen data the victim cannot simply undo by recovering their files.",
      },
      xp: 5,
    },
    // ── Reading 2: Initial access vectors ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "rw-r2",
      heading: "Getting In: Phishing, Edge-Device Exploitation, and RDP Brute Force",
      content:
        "Three vectors account for the large majority of enterprise ransomware intrusions in practice. Recognizing which one was used in a given case matters operationally, because closing only the symptom without closing the actual entry point invites the same affiliate — or the next one who buys access from the same broker — straight back through the same door.\n\n" +
        "**Phishing (T1566).** Still the single most common entry point industry-wide. A weaponized attachment or link delivers a first-stage loader, and the telltale process-tree signature — an Office application spawning a scripting engine, or a user running an executable straight out of a Downloads folder minutes after opening an email — is exactly the pattern taught in this platform's EDR-focused content. For ransomware specifically, phishing very often deliberately targets IT and helpdesk staff, precisely because their accounts tend to carry broader access and their job function makes clicking unfamiliar links and attachments part of a normal day.\n\n" +
        "**Exploitation of internet-facing edge devices (T1190, frequently followed by T1133 once a session is established).** VPN concentrators, firewalls with SSL-VPN portals, and secure file-transfer gateways are internet-facing by design and run vendor software with its own separate patch cycle from the rest of the environment. When a remote-code-execution or authentication-bypass vulnerability is publicly disclosed for one of these devices — real, well-documented examples include the 2023 Citrix NetScaler flaw nicknamed 'Citrix Bleed' and the 2024 Ivanti Connect Secure exploit chains — the window between public disclosure and mass scanning by ransomware affiliates is routinely measured in days, not months. This is exactly why unpatched, internet-facing edge devices consistently rank near the top of ransomware initial-access statistics: they are reachable from anywhere, they usually have no EDR agent running on them at all, and a successful exploit often grants a session that looks, from the inside, like an ordinary authenticated remote-access connection.\n\n" +
        "**RDP exposure (T1110 brute force or credential stuffing, followed by T1021.001 once a valid credential works).** Remote Desktop Protocol exposed directly to the internet — or reachable through a VPN with no meaningful second factor — remains one of the oldest and still most common ransomware entry points. Affiliates spray common or previously breached passwords against exposed RDP endpoints (or, increasingly, buy already-valid credentials from an Initial Access Broker) until one authenticates successfully.\n\n" +
        "**Why the vector matters for remediation, not just curiosity.** A phishing-originated case points toward user reporting, mail-gateway tuning, and the specific sender/domain involved. An edge-device case points toward an urgent patch and a full session-token invalidation on that appliance. An RDP case points toward removing the internet-facing exposure entirely and enforcing real multi-factor authentication. Treating all three the same — 'the user should have known better' — misses two out of three of the most common real entry points completely.",
      codeExample:
        "Vector                          Primary telemetry signature\n" +
        "-----------------------------------------------------------------------\n" +
        "Phishing (T1566)                 Mail gateway: malicious attachment/link\n" +
        "                                  delivered + opened; EDR process tree:\n" +
        "                                  Office app -> script host, minutes later\n" +
        "\n" +
        "Edge-device exploit (T1190)      Appliance/WAF log: exploit-pattern HTTP\n" +
        "                                  request against the management or VPN\n" +
        "                                  portal; NO phishing indicator anywhere\n" +
        "                                  for the account that logs in afterward\n" +
        "\n" +
        "RDP brute force (T1110 ->        Windows auth log: a burst of Event 4625\n" +
        "  T1021.001)                     (failed logon) against one account or\n" +
        "                                  many, then Event 4624 logon type 10\n" +
        "                                  (RemoteInteractive) once one succeeds",
      checkpoint: {
        question: "Per Reading 2, why do unpatched internet-facing edge devices (VPN portals, SSL gateways) rank so highly among real ransomware initial-access statistics?",
        options: [
          "They don't -- edge devices are actually the least common ransomware entry point of the three covered in this reading",
          "They are reachable from anywhere on the internet, usually run no EDR agent at all, and the window between a vulnerability's public disclosure and mass exploitation is often just days",
          "Because edge devices always use weaker encryption than internal servers, making any traffic through them trivial to decrypt",
          "Because edge devices are exempt from an organization's normal patch-management policy in every case",
        ],
        answer: 1,
        explanation:
          "Reading 2 was direct: these appliances are internet-facing by design, typically carry no EDR agent, run on their own vendor patch cycle, and the exploitation window after public disclosure is routinely measured in days -- a combination that makes them a consistently attractive target.",
      },
      xp: 5,
    },
    // ── Question 1 — initial access vector reasoning ─────────────────────────
    {
      type: "question" as const,
      id: "rw-q1",
      question:
        "A SOC analyst reviewing overnight VPN authentication logs sees a successful login to the corporate SSL-VPN from an unfamiliar residential IP address, followed six minutes later by that same account browsing internal file shares it has never touched before. The mail gateway logs show no phishing indicator anywhere for this user in the past month, and the VPN appliance's patch history shows it is three versions behind current, with a public CVE disclosed for that exact version eleven days ago. Based on Reading 2, what should the analyst's leading hypothesis be for the initial access vector?",
      options: [
        "Phishing -- since ransomware almost always starts with an email, the absence of any phishing indicator just means the mail gateway silently missed it, so phishing should remain the default assumption regardless of the other evidence",
        "Exploitation of the unpatched, internet-facing VPN appliance (T1190) -- the absence of a phishing indicator, the eleven-day-old public CVE, and the appliance running three versions behind current together point at edge-device exploitation rather than a user-driven action",
        "RDP brute force -- a burst of repeated authentication failures is the defining signature of brute force, and any successful login to a remote-access service should always be attributed to brute forcing by default",
        "The initial access vector doesn't matter for the investigation, since every ransomware intrusion eventually reaches the same later stages regardless of how it started",
      ],
      answer: 1,
      explanation:
        "Reading 2's whole point is that not every ransomware case starts with phishing -- here, the specific evidence (no phishing indicator anywhere, a known public CVE, an appliance three versions behind current) fits edge-device exploitation far better than an assumption. Option c is wrong because a brute-force case would show a preceding burst of failed logons (Event 4625), which isn't described here -- this is one clean successful login. And option d contradicts Reading 2 directly: identifying the actual vector determines the specific remediation (patch the appliance and invalidate its sessions here, rather than retraining a user who did nothing wrong).",
      xp: 25,
    },
    // ── Reading 3: Execution & persistence ────────────────────────────────────
    {
      type: "reading" as const,
      id: "rw-r3",
      heading: "Execution and Persistence: Surviving the First Reboot",
      content:
        "Once inside, the affiliate needs the foothold to survive a reboot and to run follow-on tooling without immediately tripping an antivirus signature — the same living-off-the-land discipline covered in this platform's Windows and Persistence content, applied specifically to the ransomware playbook.\n\n" +
        "**LOLBins reused for execution.** mshta.exe, regsvr32.exe, and rundll32.exe are all favored for running a downloader or loader without dropping an obviously-malicious standalone executable — each is a signed, legitimate Windows utility, which is exactly why file-reputation-only defenses miss this stage so often. certutil.exe gets abused for its built-in base64 decode and download functionality, pulling a second-stage tool while superficially resembling a certificate-management operation.\n\n" +
        "**Persistence — the mechanics were covered in full in the Persistence room; this is how ransomware affiliates specifically apply them.** Scheduled tasks (schtasks.exe /create, or the equivalent Task Scheduler API call, both logged as Windows Security Event 4698) are the affiliate's clear favorite for one specific reason: the very same mechanism used for a small, single-host foothold on day one gets reused on the day of impact to fire the encryptor across hundreds of hosts simultaneously, all configured to run at one scheduled time. This dual purpose is why a rash of near-identical new scheduled tasks appearing across many hosts within a short window is one of the strongest domain-wide ransomware precursor signals a SOC can catch — well before any file gets touched. Registry Run and RunOnce keys (under ...\\CurrentVersion\\Run in HKCU or HKLM) are the other commonly used option, generally favored for single-host persistence rather than the fleet-wide, timed detonation a scheduled task enables.\n\n" +
        "**The pattern that separates noise from signal.** A single new scheduled task on one workstation looks like routine IT automation and usually is. The same task name, the same action, and the same scheduled run time appearing across dozens or hundreds of hosts within a few minutes of each other is the signature that turns a low-priority note into a domain-wide emergency — the identical 'look for the pattern across hosts, not the single event in isolation' discipline this platform's EDR content already taught, now applied at fleet scale rather than to one host's sibling alerts.\n\n" +
        "**Why this stage matters even though nothing destructive has happened yet.** A persistence mechanism caught and removed here ends the intrusion cleanly. A persistence mechanism missed here is precisely what the later Impact reading in this room shows firing — simultaneously, across the entire fleet, on the day the affiliate finally pulls the trigger.",
      xp: 5,
    },
    // ── Reading 4: Discovery & credential access ──────────────────────────────
    {
      type: "reading" as const,
      id: "rw-r4",
      heading: "Discovery and Credential Access: Mapping the Domain, Then Owning It",
      content:
        "Once execution and persistence are in place, the affiliate needs to answer two questions before doing anything destructive: what does this network actually look like, and which single account can reach every host in it. Both questions point straight at Active Directory. The underlying mechanics — Kerberos tickets, LSASS, DCSync — were covered in depth in the Active Directory room; this reading is about how an affiliate applies those exact mechanics specifically toward the ransomware objective of domain-wide credential access.\n\n" +
        "**Discovery.** From a single foothold, a small set of commands maps the whole domain quickly: \"net group \\\"Domain Admins\\\" /domain\" and \"net group \\\"Enterprise Admins\\\" /domain\" enumerate the most privileged accounts directly; \"nltest /domain_trusts\" maps any trusted domains that could extend the intrusion's eventual blast radius; and \"whoami /groups\" checks the compromised account's own effective privileges — a genuinely valuable finding for an affiliate when AD group nesting quietly grants a Tier-1 helpdesk account far broader access than its job title suggests, which is exactly the kind of avoidable AD hygiene gap this room's own case study is built around. Increasingly, affiliates skip the manual commands entirely and run an automated collector (SharpHound and similar tools) that pulls this entire picture in one pass — visible on the wire, and to a Domain Controller's own logs, as a short burst of unusually high-volume LDAP queries, itself a real discovery-stage detection opportunity.\n\n" +
        "**Credential access.** Once a specific privileged target is identified, LSASS memory access (T1003.001) harvests whatever credential material is cached on that one host — GrantedAccess 0x1FFFFF, PROCESS_ALL_ACCESS, requested against lsass.exe, exactly the pattern covered in this platform's EDR investigation content. DCSync (T1003.006) goes considerably further: if the affiliate reaches an account holding replication rights (Replicating Directory Changes / Replicating Directory Changes All), they can impersonate a Domain Controller and request every domain account's password hash in a single request, without ever touching LSASS on the DC itself — the Active Directory room already covered exactly why this is so much more efficient than dumping credentials host by host.\n\n" +
        "**Why ransomware affiliates specifically need this, not just 'more access.'** Deploying an encryptor to a handful of hosts one at a time is a slow nuisance a SOC can usually catch and stop. Deploying it to every reachable server and workstation in one coordinated push — via Group Policy, PsExec, or an RMM tool, covered next in Lateral Movement — is what turns an intrusion into a company-wide outage in minutes, and that coordinated push requires exactly the kind of domain-wide administrative credential this stage exists to obtain.",
      checkpoint: {
        question: "Per Reading 4, why is DCSync (T1003.006) a more efficient credential-access method for a ransomware affiliate than dumping LSASS on individual hosts one at a time?",
        options: [
          "DCSync isn't actually more efficient -- it requires physically visiting every workstation in the domain, exactly like host-by-host LSASS dumping does",
          "DCSync lets an attacker with replication rights impersonate a Domain Controller and request every domain account's password hash in a single request, without touching LSASS on the DC at all",
          "DCSync only works against a single specific user account and provides no advantage in scale over dumping one host's LSASS memory",
          "DCSync is a Linux-only credential-access technique and has no relevance to a Windows Active Directory domain",
        ],
        answer: 1,
        explanation:
          "Reading 4 -- consistent with the Active Directory room -- is specific: an account holding replication rights can request every domain account's hash from AD's replication mechanism in one shot, which is dramatically faster than compromising and dumping LSASS on host after host to build the same picture piecemeal.",
      },
      xp: 5,
    },
    // ── Log Analysis 1: Credential access — LSASS MiniDump precursor ─────────
    {
      type: "log_analysis" as const,
      id: "rw-la1",
      heading: "Credential Access: A Domain-Wide Precursor on a Helpdesk Workstation",
      context:
        "NexaCorp's SOC is mid-incident. Three days ago, IT support technician j.reyes reported a suspicious calendar-invite email under his own helpdesk ticket. Today at 02:47 AM, Falcon fires a Critical-severity credential-access detection against his workstation, WKS-IT-0417. j.reyes holds Tier-1 helpdesk group membership, but per a legacy AD group-nesting issue the domain team has flagged for cleanup twice this year, his cached token also carries indirect Domain Admin rights. Review the detection below the way a real ransomware-precursor investigation actually runs.",
      event: lsassMiniDumpEvent,
      questions: [
        {
          question:
            "crowdstrike.ContextProcessName and crowdstrike.ParentProcessName both show cmd.exe, and crowdstrike.CommandLine shows rundll32.exe launched with the argument \"C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 ... full\". What is this specific pattern doing, and why would an affiliate prefer it over dropping a dedicated credential-dumping tool like Mimikatz?",
          options: [
            "This is a routine Windows debugging pattern that developers use constantly, and comsvcs.dll has no connection to process memory at all",
            "rundll32.exe is invoking the MiniDump export inside comsvcs.dll -- a legitimate, signed Windows DLL -- to write a full memory dump of the process with PID 668 to disk; using a built-in DLL this way avoids dropping a separate, easily-signatured credential-dumping binary onto the host",
            "comsvcs.dll is a mail server component, so this command line is unrelated to credential theft and is most likely a mail client crash handler running normally",
            "This command line cannot be evaluated at all without first knowing the file's antivirus reputation score from a third-party feed",
          ],
          answer: 1,
          explanation:
            "comsvcs.dll genuinely ships with Windows and genuinely exports a MiniDump function -- using it via rundll32.exe is a well-documented living-off-the-land credential-dumping technique precisely because it avoids ever writing a separate, obviously-malicious tool to disk. Option c invents a wrong purpose for the DLL, and option d ignores that the command line itself, read correctly, already tells the story before any external reputation lookup.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.TargetProcessName reads lsass.exe and crowdstrike.GrantedAccess reads 0x1FFFFF. Given this room's earlier reading on why ransomware affiliates specifically pursue domain-wide credential access, why does this specific access matter beyond \"this host's local secrets got dumped\"?",
          options: [
            "It doesn't matter beyond this one host -- LSASS only ever caches credential material for accounts that have never logged on anywhere else in the domain",
            "0x1FFFFF is PROCESS_ALL_ACCESS -- full control over lsass.exe, the process holding cached credential material -- and per Reading 4, this specific j.reyes account carries indirect Domain Admin rights through AD group nesting, meaning whatever gets harvested here can plausibly unlock domain-wide access, not just this one workstation",
            "GrantedAccess is purely a network-layer field describing firewall rule matches and has no relationship to process memory access at all",
            "0x1FFFFF only has meaning if the target process is a Windows service, and lsass.exe does not qualify as one",
          ],
          answer: 1,
          explanation:
            "0x1FFFFF is the PROCESS_ALL_ACCESS mask, and against lsass.exe it grants exactly the access a credential dumper needs. What raises the stakes here specifically is the context this room already established: j.reyes's account carries indirect Domain Admin rights, so this single-host credential dump is a plausible domain-wide compromise, not an isolated local event.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.FilePath for the memory dump output is C:\\ProgramData\\Adobe\\ARM\\wer4A21.tmp -- a path and naming convention that closely resembles Adobe's own legitimate crash-reporting artifacts. Why would an affiliate deliberately choose this specific location and naming pattern for the dump file?",
          options: [
            "It's a coincidence with no investigative meaning -- Windows randomly assigns temp file locations and this path was simply the next one available",
            "To blend the dump artifact in among genuine, expected Adobe Reader crash-report files, so a defender skimming file listings under C:\\ProgramData doesn't immediately flag an unfamiliar .tmp file sitting in a folder that legitimately contains many similar-looking ones",
            "Because comsvcs.dll's MiniDump function is hard-coded to only write files inside Adobe's installation directory, regardless of what the operator specifies",
            "Because writing to an Adobe-branded folder automatically grants SYSTEM-level file permissions that no other folder on the host would provide",
          ],
          answer: 1,
          explanation:
            "This is a masquerading choice, not a technical requirement -- comsvcs.dll's MiniDump function will happily write to any path supplied on the command line. Choosing a path and naming style that mimics a real, commonly-present Adobe crash-report artifact is a deliberate attempt to blend in with a folder a defender is unlikely to scrutinize file-by-file.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.PatternDispositionDescription reads \"Detected, no action taken,\" meaning Falcon only observed this LSASS access rather than stopping it. Given everything in this finding -- the LOLBin technique, the masquerading dump path, and j.reyes's indirect Domain Admin rights -- what should the analyst do immediately?",
          options: [
            "Close the detection as informational, since \"Detected, no action taken\" is Falcon's own signal that the pattern wasn't serious enough to worry about",
            "Treat every credential this account could plausibly reach as compromised right now, begin emergency credential rotation and scoping across the domain (not just this one workstation), and escalate immediately -- waiting to see what happens next only gives an affiliate more time to use exactly the access this finding shows they may already have",
            "Wait for a second, independent finding on a different host before taking any action at all, since one credential-access detection alone is never sufficient grounds to begin rotation",
            "Reimage WKS-IT-0417 immediately as the complete remediation, since credential material only ever affects the specific host it was dumped from",
          ],
          answer: 1,
          explanation:
            "\"Detected, no action taken\" means the dump was never stopped -- it raises urgency rather than lowering it. Given the domain-wide reach this specific account plausibly has, the correct response treats potentially domain-wide credentials as compromised immediately rather than waiting for further proof, and reimaging one workstation does nothing to address credentials that may already be usable against dozens of other hosts.",
          xp: 40,
        },
      ],
    },
    // ── Reading 5: Lateral movement ───────────────────────────────────────────
    {
      type: "reading" as const,
      id: "rw-r5",
      heading: "Lateral Movement: PsExec, WMI, and RDP",
      content:
        "With a privileged account in hand, the affiliate needs to reach every host they eventually intend to encrypt. In practice, three tools account for nearly all of it.\n\n" +
        "**PsExec (T1021.002, over SMB/admin shares).** A completely legitimate Sysinternals tool that IT teams use constantly for remote administration, PsExec connects to a target using the supplied credential, copies itself to the target's ADMIN$ share, and creates a Windows service to execute a command remotely. The resulting telemetry is one of the most reliable lateral-movement signatures in Windows security logging: a network logon (Event 4624, logon type 3) from the source host's IP address, followed within seconds by a new service creation (Event 7045) — typically named PSEXESVC, or a renamed variant if the affiliate customized the binary to avoid that exact string. PsExec's own legitimacy is precisely why the pattern — repetition across multiple hosts from one account within a short window, not the tool's mere presence — is what an analyst actually has to read.\n\n" +
        "**WMI (T1047).** Windows Management Instrumentation can start a process on a remote host (via a Win32_Process Create call) without creating a new service and without touching ADMIN$ the way PsExec does, which makes it noticeably quieter in traditional logging. The giveaway is usually WmiPrvSE.exe showing up as the unexpected parent of a process that has no ordinary business reason to be launched that way on that particular host.\n\n" +
        "**RDP (T1021.001).** Using the stolen credential to open a full interactive graphical session directly — logged as Event 4624 with logon type 10 (RemoteInteractive), sometimes paired with Events 4778/4779 recording session reconnect and disconnect. Interactive RDP sessions are the noisiest of the three lateral-movement methods, since a human is genuinely driving the keyboard on the other end, but they are also easy to miss entirely if nobody is specifically watching for RDP logons from accounts or source hosts that don't ordinarily use it.\n\n" +
        "**The point that ties all three together.** None of PsExec, WMI, or RDP is malicious by itself — all three are legitimate, everyday administrative tools. Exactly as with the LOLBins covered earlier in this room, the analyst's job is reading the full combination: which account, from which source, at what hour, and — critically for ransomware specifically — whether the same pattern is repeating across many hosts in a short window, which is the one thing routine, single-host IT administration essentially never looks like.",
      checkpoint: {
        question: "Per Reading 5, what is the actual signal that separates a genuine PsExec-based lateral-movement attack from an administrator's routine use of the same tool?",
        options: [
          "There is no way to tell the difference -- any PSEXESVC service creation should always be treated as a confirmed attack regardless of context",
          "The repeating pattern itself -- the same account authenticating (logon type 3) and creating a PSEXESVC service across multiple hosts within a short window -- combined with whether that account, source, and timing are actually expected, not the mere presence of PsExec",
          "PsExec is inherently malicious software, so its presence alone is always sufficient grounds to treat any finding as a confirmed attack with no further review needed",
          "Only the specific service name PSEXESVC matters -- if an attacker renames the service to anything else, the activity becomes undetectable by definition and no further signal exists",
        ],
        answer: 1,
        explanation:
          "Reading 5 was explicit that PsExec is legitimate and used constantly by IT -- the tell is the pattern (repetition across hosts, unusual account/source/timing), not the tool's identity. Option d overclaims too: a renamed service still leaves the underlying network-logon-then-service-creation pattern, which is exactly why reading the pattern matters more than matching one exact string.",
      },
      xp: 5,
    },
    // ── Question 2 — lateral movement scenario ────────────────────────────────
    {
      type: "question" as const,
      id: "rw-q2",
      question:
        "Two Windows Security logs land nine minutes apart on two different servers. On SRV-APP-14: Event 4624 (logon type 3, network logon) for NEXACORP\\j.reyes from source IP 10.30.4.61, immediately followed by Event 7045 recording a new service named PSEXESVC. Nine minutes later, the identical pattern repeats on SRV-DB-09 -- same account, same source IP, another PSEXESVC service creation. Based on Reading 5 and this room's earlier findings, what does this pair of events most likely represent?",
      options: [
        "Nothing worth investigating -- PsExec is a legitimate Sysinternals tool, so any PSEXESVC service creation should be closed automatically without further review",
        "A single administrator remotely managing two servers in the ordinary course of IT work -- logon type 3 is used constantly for routine administration, so no further check is needed",
        "The classic PsExec lateral-movement signature -- a repeating network-logon-then-PSEXESVC pattern across two hosts nine minutes apart, from the same j.reyes account this room's credential-access finding already flagged as plausibly carrying domain-wide access -- the analyst should treat this as the affiliate spreading with the stolen credential and check every other host that account has touched tonight",
        "This must already be the ransomware encryption stage in progress, since PsExec is exclusively an attacker tool and its use on two hosts means the impact stage has already begun",
      ],
      answer: 2,
      explanation:
        "PsExec is legitimate, but the identical, repeating pattern across two hosts within nine minutes -- from the exact account this room's log analysis already flagged as compromised and carrying broad reach -- is the lateral-movement signature Reading 5 described, not routine single-admin activity. Option d wrongly conflates lateral movement (spreading access) with the later, distinct Impact stage covered further on in this room -- PsExec here is being used to move and stage, not to encrypt.",
      xp: 25,
    },
    // ── Matching: lifecycle stage -> MITRE technique ─────────────────────────
    {
      type: "matching" as const,
      id: "rw-m1",
      heading: "Match the Ransomware Lifecycle Stage to Its MITRE ATT&CK Technique",
      instructions: "Match each observed behavior from this room's case to the specific MITRE ATT&CK technique it represents.",
      pairs: [
        { id: "phish", left: "Phishing email delivers the first-stage loader", right: "T1566 -- Phishing" },
        { id: "edge", left: "Affiliate exploits an unpatched, internet-facing VPN appliance", right: "T1190 -- Exploit Public-Facing Application" },
        { id: "sched", left: "Scheduled task re-launches the payload after reboot, and later fires the encryptor fleet-wide", right: "T1053.005 -- Scheduled Task" },
        { id: "lsass", left: "rundll32.exe + comsvcs.dll dumps lsass.exe's memory on one workstation", right: "T1003.001 -- LSASS Memory" },
        { id: "dcsync", left: "Attacker requests replication rights from a Domain Controller to pull every password hash at once", right: "T1003.006 -- DCSync" },
        { id: "psexec", left: "PsExec pushes access to additional hosts using a stolen credential", right: "T1021.002 -- SMB/Windows Admin Shares" },
        { id: "vss", left: "vssadmin deletes every shadow copy on a host before encryption starts", right: "T1490 -- Inhibit System Recovery" },
        { id: "clearlog", left: "Windows Security event log is cleared right after the intrusion", right: "T1070.001 -- Clear Windows Event Logs" },
        { id: "exfil", left: "Bulk data is copied to a cloud remote using rclone before the ransom note ever appears", right: "T1567.002 -- Exfiltration to Cloud Storage" },
      ],
      explanation:
        "Notice how many different ATT&CK tactics one ransomware intrusion touches -- Initial Access, Persistence, Credential Access, Lateral Movement, Defense Evasion, and Exfiltration all show up before Impact ever fires. This is exactly why treating ransomware as 'one detection at the encryption stage' misses the five or six earlier chances a SOC actually had to stop it.",
      xp: 35,
    },
    // ── Reading 6: Defense evasion ─────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "rw-r6",
      heading: "Defense Evasion: Deleting Recovery, Disabling Detection, Erasing Evidence",
      content:
        "Before detonating the encryptor, a competent affiliate spends real effort making recovery as hard as possible and leaving the SOC as little as possible to work with. Three specific techniques account for most of what shows up in real cases.\n\n" +
        "**Shadow copy deletion (T1490 — Inhibit System Recovery).** Windows' Volume Shadow Copy Service keeps point-in-time snapshots that would otherwise let a victim restore pre-encryption versions of their own files in minutes, without needing any external backup at all. \"vssadmin.exe delete shadows /all /quiet\" (or the WMI equivalent, or wbadmin deleting the backup catalog outright) removes exactly that safety net. As this platform's forensics content already covers, this single command line — launched from an unexpected parent process, shortly before mass file activity begins, on a host that isn't a documented backup server running its normal retention job — is one of the single strongest ransomware precursor signals a detection rule can fire on, precisely because there are very few legitimate reasons for it to run outside that one narrow, scheduled context.\n\n" +
        "**Disabling security tooling (T1562.001 — Impair Defenses).** An affiliate with sufficient privilege attempts to stop or uninstall the EDR/AV agent outright, disable Windows Defender's real-time protection (for example, via \"Set-MpPreference -DisableRealtimeMonitoring $true\"), or add broad path exclusions covering wherever the encryptor is about to run from. Modern EDR platforms increasingly ship tamper protection specifically to resist exactly this — which is part of why, in a real fleet-wide incident, some hosts end up fully protected while others, where tamper protection was misconfigured, out of date, or simply never deployed, do not.\n\n" +
        "**Clearing evidence (T1070.001 — Clear Windows Event Logs).** \"wevtutil cl Security\" — often run against System and Application alongside it — wipes the very log a defender would normally use to reconstruct what happened. But, as this platform's forensics content already established, the act of clearing a log is itself logged: a fresh Event ID 1102 records exactly who cleared it and precisely when, turning an erasure attempt into a precise timestamp for exactly where in every OTHER available log source to keep looking.\n\n" +
        "**Why this stage is worth a dedicated read, not just a footnote.** Every one of these three techniques is loud in its own way — a shadow-copy deletion command, a security-tooling change, a log-clear event — and every one of them, done outside its narrow legitimate context, is close to unambiguous. This is genuinely one of the last stages where a SOC that's paying attention can still catch the intrusion before Impact, and it's exactly why the Ordering exercise that follows asks you to place it correctly in the full sequence.",
      xp: 5,
    },
    // ── Ordering: full lifecycle sequence ─────────────────────────────────────
    {
      type: "ordering" as const,
      id: "rw-o1",
      heading: "Order the Full Ransomware Attack Lifecycle",
      instructions: "Arrange these nine stages in the order a real double-extortion ransomware intrusion actually runs, from foothold to extortion.",
      items: [
        { id: "init", text: "Initial Access -- a phishing email or an unpatched edge-device vulnerability delivers a foothold" },
        { id: "exec", text: "Execution -- a LOLBin (rundll32.exe, mshta.exe, certutil.exe) runs the first-stage payload" },
        { id: "persist", text: "Persistence -- a scheduled task or Run key ensures the foothold survives a reboot" },
        { id: "discover", text: "Discovery -- AD reconnaissance maps groups, trusts, and privileged accounts" },
        { id: "cred", text: "Credential Access -- LSASS is dumped or DCSync is run to harvest domain-wide credentials" },
        { id: "lateral", text: "Lateral Movement -- PsExec, WMI, or RDP spreads access to additional hosts using the stolen credential" },
        { id: "evasion", text: "Defense Evasion -- shadow copies are deleted, EDR is disabled, and event logs are cleared" },
        { id: "exfil", text: "Exfiltration -- staged, compressed data is pushed out via rclone or a similar tool, before encryption starts" },
        { id: "impact", text: "Impact and Extortion -- the encryptor runs fleet-wide and the ransom note appears, referencing already-published stolen data" },
      ],
      correct_order: ["init", "exec", "persist", "discover", "cred", "lateral", "evasion", "exfil", "impact"],
      explanation:
        "Each stage depends on what the previous one produced: execution needs the foothold Initial Access delivered; Persistence protects that foothold before the affiliate risks losing it to a reboot; Discovery and Credential Access together are what make fleet-wide Lateral Movement possible in the first place; Defense Evasion is timed deliberately late, right before the noisiest stages, to blind the SOC for as long as possible; and -- as Reading 7 covers next -- Exfiltration now routinely runs before Impact rather than alongside it, because a well-organized affiliate wants the leverage fully banked before risking the detection an obvious mass-encryption event almost guarantees.",
      xp: 35,
    },
    // ── Reading 7: 2025 exfiltration-first model ──────────────────────────────
    {
      type: "reading" as const,
      id: "rw-r7",
      heading: "The Exfiltration-First Model: Why the Order of Operations Changed",
      content:
        "Reading 1 introduced double extortion as a concept. This reading covers how it actually plays out in the telemetry, and why the order of operations has shifted meaningfully in recent years.\n\n" +
        "**The older model (roughly 2019-2021).** Exfiltrate a small sample of data as proof, encrypt everything, and reveal the leak-site threat only after the ransom note appears. Encryption was the main event; exfiltration was close to an afterthought bolted on for extra leverage right at the end.\n\n" +
        "**The current model.** Staging and exfiltration now routinely happen well before encryption — sometimes days before — because a well-organized affiliate wants the leverage fully banked before risking the early detection that the noisiest, most obviously destructive stage of the whole intrusion almost guarantees. Practically, this means high-value shares get archived first (7-Zip or WinRAR compressing a target directory into a handful of large files — itself a detectable pattern, since a burst of .7z or .rar file creation in a directory that never previously held any is unusual on its own), then the archive gets pushed out using a purpose-built transfer tool. rclone and MEGAcmd are the two most consistently observed in real cases, though WinSCP, rsync, and outright abuse of an already-installed legitimate sync client all appear too.\n\n" +
        "**The 'encryption-optional' trend.** A growing share of ransomware-branded campaigns have, in some cases, skipped the encryption stage entirely and gone straight to pure extortion: steal the data, threaten to leak it, never touch a single file's contents. Operationally this is faster for the affiliate, avoids ever producing the unmistakable, unambiguous signal a mass file-encryption event generates, and still delivers the same leverage as long as the stolen data is genuinely sensitive. This doesn't mean encryption is disappearing — it remains extremely common, including in this room's own case study — but it does mean an analyst who treats 'no files have been encrypted yet' as 'we're safe' is working from an outdated model of how these intrusions actually play out.\n\n" +
        "**Why this matters more than anything else in this room, operationally.** The exfiltration-staging window is very often the last point in the entire intrusion where stopping the attack genuinely changes the outcome. Once encryption starts, the damage to availability is largely locked in regardless of what happens next — but a large, anomalous outbound transfer caught and cut off during staging can mean the leverage the attacker was counting on never actually leaves the building at all. This is exactly why the log analysis task that follows this reading sits at the exfiltration stage, not the encryption stage — it is the single highest-value place in the whole chain for a SOC to actually change how the story ends.",
      diagram:
        "flowchart TB\n" +
        "  subgraph OLD[\"Encryption-first (2019-2021 model)\"]\n" +
        "    O1[\"Foothold + limited recon\"] --> O2[\"Encrypt fleet-wide\"] --> O3[\"Drop note + exfil only a small proof sample, almost simultaneously\"]\n" +
        "  end\n" +
        "  subgraph NEW[\"Exfiltration-first (current model)\"]\n" +
        "    N1[\"Foothold + full AD recon + credential access\"] --> N2[\"Stage archives, exfiltrate the real payload -- hours to days\"] --> N3[\"Encrypt fleet-wide, days later\"] --> N4[\"Drop note referencing already-published leak-site proof\"]\n" +
        "  end\n",
      diagramCaption: "How the order of operations shifted from encryption-first to exfiltration-first",
      checkpoint: {
        question: "Per Reading 7, why does the exfiltration-staging window matter more operationally than almost any other stage in the ransomware lifecycle?",
        options: [
          "It doesn't -- every stage of a ransomware intrusion carries exactly equal operational importance for the SOC, with no single stage mattering more than any other",
          "It is very often the last point in the intrusion where stopping the attack genuinely changes the outcome -- once encryption starts, availability damage is largely locked in, but a caught exfiltration attempt can mean the attacker's leverage never actually leaves the network",
          "It matters only because exfiltrated data is always immediately deleted from the attacker's infrastructure the moment a SOC detects it, undoing the theft completely",
          "It matters less than the encryption stage, since only encrypted files ever cause any real business impact to the victim organization",
        ],
        answer: 1,
        explanation:
          "Reading 7 was explicit about this: encryption's damage to availability is largely fixed once it starts, but exfiltration caught during staging can prevent the double-extortion leverage from ever existing in the attacker's hands at all -- which is exactly why it deserves this much attention rather than being treated as a footnote before the 'real' encryption event.",
      },
      xp: 5,
    },
    // ── Log Analysis 2: Exfiltration staging via rclone ──────────────────────
    {
      type: "log_analysis" as const,
      id: "rw-la2",
      heading: "Exfiltration Staging: Bulk Data Leaving the Finance File Server",
      context:
        "It's 04:58 AM -- roughly two hours after the credential-access finding on WKS-IT-0417. Falcon fires a High-severity Exfiltration-to-Cloud-Storage detection on SRV-FILES-04, the Finance department's file server. Review the detection below using everything this room has already established about this intrusion.",
      event: rcloneExfilEvent,
      questions: [
        {
          question:
            "crowdstrike.FilePath shows the transfer tool running from C:\\Users\\Public\\rclone.exe, launched under cmd.exe rather than any documented backup process. What should this specific detail make an analyst want to check first -- and what should it NOT be treated as?",
          options: [
            "It should be treated as absolute proof of malicious activity on its own, since rclone.exe is malware by definition and its mere presence anywhere on a host is always a confirmed compromise",
            "It should prompt checking whether this file server has any legitimate, documented reason to run a transfer tool from a generic public user folder rather than a normal installed-software location -- rclone itself is a legitimate, widely-used tool, so the unusual location and launch method are the signal worth investigating, not the tool's name",
            "It should be dismissed immediately, since any file located under C:\\Users\\Public is automatically trusted by Windows and cannot be flagged by security tooling",
            "It should only be investigated if the file's SHA256 hash comes back as a known-bad signature in a public threat intelligence feed -- otherwise no further review is warranted",
          ],
          answer: 1,
          explanation:
            "rclone is genuinely legitimate, widely-used software -- this room's own analyst_choice task later shows a completely benign use of the identical tool. What's actually worth checking here is the unusual location (a generic Public user folder rather than an installed-software path) and the fact it was launched manually under cmd.exe rather than through any documented process -- exactly the kind of context-dependent reasoning this room has taught throughout, not a name-based reflex in either direction.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.CommandLine reads: rclone.exe copy \\\\SRV-FILES-04\\Shared\\Finance Q4 gdrive-sync:archive --config C:\\Users\\Public\\rc.conf -q --transfers 16. What does this specific command line reveal about the scope and intent of the transfer?",
          options: [
            "Nothing meaningful -- rclone command lines are generated randomly and carry no information about what is actually being copied or where it is going",
            "It targets specifically the Finance department's Q4 share as the source, uses \"-q\" (quiet mode, suppressing normal console output) and a high transfer-parallelism setting to move data quickly, and sends it to a remote named \"gdrive-sync\" -- a name with no match in any list of NexaCorp's approved cloud-storage destinations",
            "It proves the transfer is completely safe, since the word \"sync\" in the remote name \"gdrive-sync\" confirms this is an official, IT-sanctioned Google Drive backup integration",
            "The --transfers 16 flag is a Windows-only network diagnostic setting used exclusively for testing internet connectivity, unrelated to file transfer",
          ],
          answer: 1,
          explanation:
            "Reading the command line closely -- not just noting that rclone ran -- shows a specific, high-value target (Finance Q4), deliberate quiet/high-throughput settings, and a destination remote name that doesn't match anything on NexaCorp's approved list. A friendly-sounding remote name proves nothing about legitimacy on its own, which is exactly the trap option c falls into.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.UserName shows NEXACORP\\j.reyes -- the exact account this room's credential-access finding on WKS-IT-0417 flagged, two hours earlier, as carrying indirect Domain Admin rights. Why does this specific correlation matter more than treating this finding as a brand-new, unrelated case?",
          options: [
            "It doesn't matter -- the two hosts and events are far enough apart in time and location that they should always be triaged as completely separate, unrelated cases",
            "It confirms this is very likely the same intrusion continuing to unfold: the credential harvested from WKS-IT-0417 is now plausibly being used to reach and exfiltrate from a file server two hours later, which is exactly the domain-wide reach Reading 4 warned this account's privilege-nesting issue could enable",
            "It matters only for billing purposes, since CrowdStrike licenses are tracked per user account regardless of what activity is observed",
            "It proves the two events must have been performed by two different people who happen to share login credentials, since one person cannot plausibly act on two hosts in one night",
          ],
          answer: 1,
          explanation:
            "Treating separated-in-time, separated-in-host findings as unrelated is exactly the sibling-alert mistake this platform's EDR content warned against -- here, the shared account is the thread connecting a domain-wide credential theft to its very next plausible use two hours later, which is precisely the kind of correlation a real investigation is built to catch.",
          xp: 30,
        },
        {
          question:
            "it_verify_result reads \"unverified,\" and it_verify_message notes the file server's only documented backup tool is the nightly Veeam Agent job -- not rclone. Combined with everything else in this finding, what should the analyst do right now?",
          options: [
            "Wait to see whether encryption activity appears anywhere in the fleet before taking any action on this specific finding, since exfiltration alone is never worth an urgent response on its own",
            "Treat this as active exfiltration staging tied to the same intrusion as the earlier credential-access finding -- immediately cut off this host's ability to reach the external destination, alert IR now, and do not wait for the encryption stage that Reading 7 explained may not even be the attacker's next move",
            "Approve the transfer as legitimate, since rclone is a real, commonly-used enterprise tool and its presence alone is sufficient grounds to assume it belongs to an authorized process",
            "Close the finding without escalation, since \"unverified\" only means the IT ticketing system hasn't been checked yet, not that anything is actually wrong",
          ],
          answer: 1,
          explanation:
            "This is exactly the highest-value moment Reading 7 described: staging caught before encryption is the point where the outcome can still change. Waiting for encryption to appear before acting (option a) throws away that window entirely, and Reading 7 was explicit that some affiliates skip encryption altogether -- there may be no later, more obvious signal coming at all.",
          xp: 40,
        },
      ],
    },
    // ── Analyst Choice: FP trap — legitimate migration rclone job ────────────
    {
      type: "analyst_choice" as const,
      id: "rw-ac1",
      heading: "Verdict: An rclone Cloud-Storage Detection on an Archive Server",
      scenario:
        "Falcon fires a High-severity Exfiltration-to-Cloud-Storage detection on SRV-ARCHIVE-02 -- the exact technique family this room's exfiltration-staging finding on SRV-FILES-04 was just confirmed as a true positive for. Review the detection before deciding whether this one is a true positive or a false positive.",
      event: migrationRcloneEvent,
      correct_verdict: "false_positive",
      explanation:
        "crowdstrike.FilePath is C:\\Program Files\\RecordsMigration\\rclone.exe -- a proper installed-software location, not a generic Public folder. crowdstrike.ParentProcessName is MigrationScheduler.exe, a known, documented process, not cmd.exe launched manually. crowdstrike.CommandLine targets a legacy project archive and pushes it to \"sharepoint-nexacorp\" -- NexaCorp's own licensed, recognized SharePoint tenant, not an unrecognized personal cloud remote. crowdstrike.UserName is svc-migrate, a documented service account, not a privileged human account that was just flagged elsewhere in an active incident. And it_verify_result confirms change ticket CHG-40881 authorizing exactly this project, on this host, on this schedule.",
      fp_trap:
        "This detection uses the identical technique family -- and the identical tool, rclone -- as the confirmed true-positive exfiltration finding earlier in this room, which makes escalating it on reflex extremely tempting. But the specific fields tell two very different stories: proper install location vs. a generic Public folder, a documented scheduler process vs. manual cmd.exe launch, the org's own recognized SharePoint tenant vs. an unrecognized remote name, a documented migration service account vs. a privileged account already flagged in an active incident, and a confirmed change ticket vs. no ticket at all. Escalating every rclone-to-cloud pattern without checking these fields either buries the SOC in noise on every legitimate backup or migration job, or -- just as dangerously -- teaches the team to stop reading past the tool's name entirely, which is exactly the habit that would let a real exfiltration attempt hide behind a routine-sounding process.",
      xp: 35,
    },
    // ── Reading 8: Impact, extortion, and the full-chain playbook ────────────
    {
      type: "reading" as const,
      id: "rw-r8",
      heading: "Impact and Extortion: Encryption Mechanics and the Full-Chain Playbook",
      content:
        "**How the encryption actually works (T1486).** Production ransomware doesn't encrypt with one slow, crackable algorithm — it uses a fast symmetric cipher (commonly AES or ChaCha20) to encrypt each file's contents quickly at scale, then wraps that per-file or per-host symmetric key with an asymmetric public key (RSA or ECC) baked into the encryptor binary at build time. The matching private key never touches the victim's environment at all — it exists only on the attacker's own infrastructure. This is exactly why 'just recover the key from memory' almost never works at any real scale, and why free public decryptors are genuinely rare: they normally exist only because researchers found an actual implementation flaw in one specific family's build, not because the underlying cryptography itself was ever broken.\n\n" +
        "**What the moment of impact looks like in telemetry.** A mass, rapid file-modification and rename event from a single process across an enormous number of files in a short window, almost always paired with a new, previously-unseen extension appended to every file it touches, and a note file dropped into common, highly visible locations. Modern EDR platforms specifically watch for this rename-rate spike as a distinct, high-confidence behavioral signature — independent of the specific binary's hash or file name, which is exactly why disguising the binary's name (as this room's own case study shows) slows detection down but does not defeat it.\n\n" +
        "**The extortion note and what follows it.** The note directs the victim toward a negotiation channel — often a Tor-hosted chat portal — and, in a double-extortion case, references a leak site where a sample of the stolen data is already published as proof, with a countdown before the rest goes up. Some groups add further pressure on top of this: contacting the victim's own customers or regulators directly, or threatening a denial-of-service against public-facing systems — a pattern industry reporting sometimes calls triple extortion.\n\n" +
        "**The full-chain playbook — what the SOC actually does at every stage, not just at the end.**\n\n" +
        "**The governance line that closes this room.** Whether to pay a ransom is not a SOC decision. It belongs to executive leadership, legal counsel, often the organization's cyber insurer, and — in many jurisdictions — carries real regulatory and even sanctions-related considerations depending on who the threat actor turns out to be. The SOC's job through every single stage of this room has been to produce the facts that decision actually needs: what got in, what was touched, what was taken, and what is and isn't still actively spreading right now. Producing those facts quickly and accurately is the job. Making the payment call is someone else's.",
      codeExample:
        "Stage              Detection point (what a SOC actually sees)        Analyst action\n" +
        "-----------------------------------------------------------------------------------------\n" +
        "Initial Access      Phishing click, edge-device exploit pattern,       Contain the account/session; patch or\n" +
        "                    or RDP brute-force burst                          isolate the exploited entry point\n" +
        "\n" +
        "Execution/           LOLBin launched with unusual arguments;           Kill the process; preserve the sample\n" +
        "Persistence          new scheduled task or Run key (Event 4698)       for later correlation\n" +
        "\n" +
        "Discovery/Cred        LSASS access (0x1FFFFF), DCSync request,        Treat reachable credentials as\n" +
        "Access                or LDAP-query burst against a DC                compromised; begin rotation now\n" +
        "\n" +
        "Lateral Movement      Repeating 4624(type3)+7045 pattern (PsExec),    Isolate the source host; scope every\n" +
        "                      WmiPrvSE anomaly, or unexpected 4624 type10     host the credential has reached\n" +
        "\n" +
        "Defense Evasion       vssadmin/wbadmin shadow-copy delete,            Escalate immediately -- this is one\n" +
        "                      security-tooling disabled, or a fresh 1102     of the last quiet windows before Impact\n" +
        "\n" +
        "Exfiltration          Large outbound transfer to an unrecognized     Cut external network access for the\n" +
        "                      cloud remote via rclone/MEGA/similar           host now; this is the highest-value\n" +
        "                                                                     stage left to actually change the outcome\n" +
        "\n" +
        "Impact                Mass file rename/modify spike + new extension  Isolate every affected and targeted\n" +
        "                      + ransom note drop                             host; hand facts, not decisions, to IR",
      xp: 5,
    },
    // ── Log Analysis 3: Impact — fleet-wide encryption ────────────────────────
    {
      type: "log_analysis" as const,
      id: "rw-la3",
      heading: "Impact: The Encryptor Fires Across the Fleet",
      context:
        "It's 07:12 AM. In the last five minutes, Falcon has fired sixty-one near-identical Critical detections across the NexaCorp fleet. Twelve minutes earlier, Windows Security Event 4698 recorded a new scheduled task -- \\Microsoft\\Windows\\WindowsUpdate\\wuauclt32Check -- created almost simultaneously on more than 140 hosts, each configured to fire at 07:00 running as SYSTEM. This is the same domain-wide push the credential theft on WKS-IT-0417 and the exfiltration staging on SRV-FILES-04 were building toward. Review this one host's detection the way triage during an active mass-encryption event actually happens: fast, but not blind.",
      event: encryptorImpactEvent,
      questions: [
        {
          question:
            "crowdstrike.FileName reads wuauclt32.exe and crowdstrike.FilePath reads C:\\Windows\\Temp\\wuauclt32.exe. What is suspicious about this specific name-and-path combination?",
          options: [
            "Nothing -- Windows Update's client legitimately updates itself from the Temp folder during routine patch cycles, so this is completely ordinary",
            "The real Windows Update client is named wuauclt.exe and lives in C:\\Windows\\System32, not C:\\Windows\\Temp -- this binary's name is a close-but-not-exact imitation, and its location is a place a genuine system component would never actually run from, both of which are deliberate masquerading choices",
            "The .exe extension itself is inherently suspicious, since no legitimate Windows system process is ever packaged as a standalone executable file",
            "wuauclt32.exe cannot be evaluated without first checking whether Windows Temp folders are writable, since writability alone determines whether a file is malicious",
          ],
          answer: 1,
          explanation:
            "This is textbook masquerading: a name close enough to a real system process to pass a quick glance (wuauclt.exe vs. wuauclt32.exe), combined with a location -- C:\\Windows\\Temp -- that the genuine Windows Update client never actually runs from. Both details together are the tell, not either one in isolation.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.CommandLine reads: wuauclt32.exe --path C:\\ --ext .a8f2e91c --note RESTORE-FILES-a8f2e91c.txt --skip C:\\Windows,C:\\ProgramData,C:\\$Recycle.Bin --threads 24. What do these specific arguments reveal about the tooling and the affiliate's intent?",
          options: [
            "Nothing -- these arguments are randomly generated and have no bearing on what the binary actually does when executed",
            "This is a purpose-built, configurable ransomware binary: it targets the entire C:\\ drive, appends a distinct extension and drops a matching note, and deliberately excludes core system directories -- keeping the host functional enough to boot and actually display the ransom note, rather than indiscriminately destroying the system the way a wiper would",
            "The --skip flag proves this activity is completely benign, since any tool that avoids the Windows and ProgramData folders is, by definition, not malware",
            "--threads 24 is a network configuration setting controlling how many VPN tunnels the host can open simultaneously, unrelated to file operations",
          ],
          answer: 1,
          explanation:
            "Real ransomware encryptors are commonly built with exactly this kind of command-line configurability -- target path, extension, note filename, and directories to skip. The deliberate exclusion of system directories is a functional choice, not a sign of benign intent: a host that can still boot and display the note is more useful to the affiliate's extortion goal than one that's been destroyed outright, which is also the key distinction between ransomware and a wiper.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.PatternDispositionDescription reads \"Detected, kill process\" -- this specific host was actually blocked, unlike the earlier findings in this room. Given the sixty other near-identical detections firing in the same five minutes mentioned in the context, what should the analyst NOT conclude from this one host being protected?",
          options: [
            "That the incident is now over, since the encryptor was successfully blocked on this specific host",
            "That every other host targeted by the same scheduled task was necessarily blocked too, since EDR policy and tamper-protection state are always identical across an entire fleet",
            "That EDR tuning, rollout state, and tamper-protection configuration can genuinely differ host to host -- so this one successful block says nothing about the sixty-plus other near-simultaneous detections, and the very next step is checking which of the roughly 140 targeted hosts were NOT protected",
            "That this finding can be closed without any further review, since a \"kill process\" disposition always means the entire fleet-wide incident has been fully contained",
          ],
          answer: 2,
          explanation:
            "Reading 6 already established that tamper protection and tooling state can vary by host -- this single successful block tells the analyst nothing about the other targeted hosts. The correct next step is exactly what option c describes: immediately check the outcome on every other host the same scheduled task reached, not assume uniform protection across the fleet.",
          xp: 35,
        },
      ],
    },
    // ── Question 3 — containment & escalation decision ────────────────────────
    {
      type: "question" as const,
      id: "rw-q3",
      question:
        "It's now confirmed: credentials were dumped from an IT workstation, a domain-privileged account staged and exfiltrated roughly 85 GB of the Finance share to an unrecognized cloud remote, and an encryptor has begun running on dozens of hosts -- some successfully blocked by EDR, some not. A ransom note referencing a leak site has appeared. Based on Reading 8's playbook, what is the correct sequence of actions for the SOC right now?",
      options: [
        "Immediately negotiate with the attacker through the leak-site chat to buy time, since the SOC is best positioned to make the payment decision on the organization's behalf without waiting for legal or executive input",
        "Network-isolate every host still showing active or attempted encryption, scope which hosts were actually hit versus merely targeted, preserve evidence, and hand IR/legal/executives a clear technical picture -- blast radius, confirmed exfiltrated data, and IOCs -- since the payment decision itself belongs to them, not the SOC",
        "Power off every server in the environment immediately, including hosts with no sign of compromise at all, since a full shutdown is always the safest first move regardless of what has or hasn't been confirmed as affected",
        "Do nothing further until an attacker-supplied decryption tool is verified to work, since there is no remaining value in containment once encryption has already started on some hosts",
      ],
      answer: 1,
      explanation:
        "Option b matches Reading 8's playbook directly: contain the still-active spread, scope accurately, preserve evidence, and deliver facts -- not a payment decision -- to the people actually authorized to make that call. Option a hands the SOC a decision and a level of external contact it should never have. Option c is disproportionate: it destroys volatile evidence on unaffected hosts for no benefit, and shutting down hosts still mid-encryption doesn't undo damage already done while complicating recovery. Option d wrongly treats containment as pointless once some hosts are hit, when stopping the spread to the hosts NOT yet encrypted is exactly the highest-value action still available.",
      xp: 30,
    },
    // ── Flag ───────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "rw-f1",
      prompt:
        "Look at the Impact-stage finding on WKS-HR-0233 (the encryptor detection). According to the raw crowdstrike.CommandLine field, what exact file extension does the encryptor append to every file it processes?",
      answer: ".a8f2e91c",
      hint: "Look for the --ext argument inside crowdstrike.CommandLine on the WKS-HR-0233 detection.",
      xp: 25,
    },
  ],
};

export const roomsBatch33 = [ransomwareLifecycleRoom];
