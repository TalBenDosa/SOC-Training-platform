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
      sha256: "a27e6a7fb13a9e4ae6d0c447e4a253358e3b79c26939c7a209a29fce082a7c7b",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessAccess",
    "crowdstrike.DetectId": "ldt:fa6d8dc900d25da49a4e0f3e305893c1:41207",
    "crowdstrike.IncidentId": "inc:fa6d8dc900d25da49a4e0f3e305893c1:20260414",
    "crowdstrike.SeverityName": "Critical",
    "crowdstrike.Tactic": "Credential Access",
    "crowdstrike.Technique": "OS Credential Dumping",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "rundll32.exe",
    "crowdstrike.ParentProcessName": "cmd.exe",
    "crowdstrike.FileName": "rundll32.exe",
    "crowdstrike.FilePath": "C:\\Windows\\System32\\rundll32.exe",
    "crowdstrike.CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 C:\\ProgramData\\Adobe\\ARM\\wer4A21.tmp full",
    "crowdstrike.SHA256HashData": "a27e6a7fb13a9e4ae6d0c447e4a253358e3b79c26939c7a209a29fce082a7c7b",
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
    cmdline: "rclone.exe copy \\\\SRV-FILES-04\\Shared\\Finance-Q4 gdrive-sync:archive --config C:\\Users\\Public\\rc.conf -q --transfers 16",
    user: "NEXACORP\\j.reyes",
    hash: {
      sha256: "a2509bcefee31d3665c75a32efd9aad328b4a17611d0872dea92725027c4da7d",
    },
  },
  network: {
    domain: "gdrive-sync-relay.net",
    bytes_out: 91_483_200_000,
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.DetectId": "ldt:57b56a488e64a557b01f04a564bb90f1:52918",
    "crowdstrike.IncidentId": "inc:57b56a488e64a557b01f04a564bb90f1:20260414",
    "crowdstrike.SeverityName": "High",
    "crowdstrike.Tactic": "Exfiltration",
    "crowdstrike.Technique": "Exfiltration to Cloud Storage",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "cmd.exe",
    "crowdstrike.ParentProcessName": "cmd.exe",
    "crowdstrike.FileName": "rclone.exe",
    "crowdstrike.FilePath": "C:\\Users\\Public\\rclone.exe",
    "crowdstrike.CommandLine": "rclone.exe copy \\\\SRV-FILES-04\\Shared\\Finance-Q4 gdrive-sync:archive --config C:\\Users\\Public\\rc.conf -q --transfers 16",
    "crowdstrike.SHA256HashData": "a2509bcefee31d3665c75a32efd9aad328b4a17611d0872dea92725027c4da7d",
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
      sha256: "b7ea7072c3e72d74a39dcaa4f8e36db29b556f0eeef3b4e58dcf781f4b079a6b",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.DetectId": "ldt:f3f2021bc27e074e7307ee45bbeee342:33104",
    "crowdstrike.IncidentId": "inc:f3f2021bc27e074e7307ee45bbeee342:20260302",
    "crowdstrike.SeverityName": "High",
    "crowdstrike.Tactic": "Exfiltration",
    "crowdstrike.Technique": "Exfiltration to Cloud Storage",
    "crowdstrike.PatternDispositionDescription": "Detected, no action taken",
    "crowdstrike.ContextProcessName": "MigrationScheduler.exe",
    "crowdstrike.ParentProcessName": "MigrationScheduler.exe",
    "crowdstrike.FileName": "rclone.exe",
    "crowdstrike.FilePath": "C:\\Program Files\\RecordsMigration\\rclone.exe",
    "crowdstrike.CommandLine": "rclone.exe copy D:\\Archive\\Legacy-Projects sharepoint-nexacorp:RecordsMigration\\Legacy --config C:\\ProgramData\\RecordsMigration\\rclone.conf --transfers 8 --log-file C:\\ProgramData\\RecordsMigration\\logs\\run-0302.log",
    "crowdstrike.SHA256HashData": "b7ea7072c3e72d74a39dcaa4f8e36db29b556f0eeef3b4e58dcf781f4b079a6b",
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
      sha256: "8b138f3271c3de83fcc298c298e201cf8a0fe6fac47ae97d5b8e4694ab636bee",
    },
  },
  raw: {
    "crowdstrike.event_simpleName": "ProcessRollup2",
    "crowdstrike.DetectId": "ldt:e45507bc3ab882018097c96ef655b20b:67350",
    "crowdstrike.IncidentId": "inc:e45507bc3ab882018097c96ef655b20b:20260414",
    "crowdstrike.SeverityName": "Critical",
    "crowdstrike.Tactic": "Impact",
    "crowdstrike.Technique": "Data Encrypted for Impact",
    "crowdstrike.PatternDispositionDescription": "Detected, kill process",
    "crowdstrike.ContextProcessName": "svchost.exe",
    "crowdstrike.ParentProcessName": "svchost.exe",
    "crowdstrike.FileName": "wuauclt32.exe",
    "crowdstrike.FilePath": "C:\\Windows\\Temp\\wuauclt32.exe",
    "crowdstrike.CommandLine": "wuauclt32.exe --path C:\\ --ext .a8f2e91c --note RESTORE-FILES-a8f2e91c.txt --skip C:\\Windows,C:\\ProgramData,C:\\$Recycle.Bin --threads 24",
    "crowdstrike.SHA256HashData": "8b138f3271c3de83fcc298c298e201cf8a0fe6fac47ae97d5b8e4694ab636bee",
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
        question: "A victim restores every encrypted server from clean, immutable backups within a day and refuses to pay. Per Reading 1, what leverage was double extortion designed to keep in the affiliate's hands in exactly this situation?",
        options: [
          "The threat of a second encryption wave, since the affiliate's persistence usually survives a backup restore",
          "A copy of sensitive data stolen before encryption, which no restore undoes and which can go up on a leak site",
          "The decryption key's value for the endpoints the backups missed, since backups rarely cover every laptop",
          "Control of the backups themselves, since affiliates now encrypt the backup repository before production",
        ],
        answer: 1,
        explanation:
          "Reading 1 was explicit: once good backups made 'just restore and ignore the note' viable, operators added leverage that survives even a clean restore -- stolen data the victim cannot undo by recovering files. A second encryption wave is a re-infection risk, not the leverage double extortion adds. The key's value for endpoints the backups missed is still encryption leverage, the very thing a restore defeats. Encrypting the backup repository is a real tactic, but this victim's immutable backups survived, so it is not the leverage left in this case.",
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
        question: "Per Reading 2, which combination of properties makes unpatched internet-facing edge devices (VPN portals, SSL gateways) such a frequent ransomware entry point?",
        options: [
          "They cache every remote user's domain password, so one exploit yields domain-wide credentials as a DCSync would",
          "They are reachable from anywhere, usually run no EDR agent, and are mass-exploited within days of a CVE's disclosure",
          "Their accounts mostly belong to IT and helpdesk staff, the group that ransomware phishing deliberately targets first",
          "They follow the workstation patch cycle, so one missed monthly update leaves them exposed for a whole month",
        ],
        answer: 1,
        explanation:
          "Reading 2 was direct: these appliances are internet-facing by design, typically carry no EDR agent, run on their own vendor patch cycle, and the exploitation window after public disclosure is routinely measured in days. Domain-wide credential harvesting is what Credential Access (LSASS, DCSync) does later -- an exploit grants a session, not every user's password. Targeting IT and helpdesk staff is how Reading 2 describes phishing, a different vector. And the reading says edge devices run their own separate vendor patch cycle, not the workstation one.",
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
        "Phishing (T1566) -- a mail gateway can silently miss a delivered message, so the lack of a recorded indicator does not rule it out and the user should be handled as a phishing victim first",
        "Exploitation of the unpatched, internet-facing VPN appliance (T1190) -- the version is behind current with a public CVE disclosed eleven days ago, and no phishing trace exists for this user",
        "VPN brute force or password spraying (T1110) -- a first successful login from an unfamiliar residential IP is the typical outcome of credential guessing, so the vector should be treated as guessed credentials",
        "Vector attribution is a post-incident task -- at triage the analyst should only contain the account and leave any initial-access hypothesis to the forensics team once the investigation closes",
      ],
      answer: 1,
      explanation:
        "Reading 2's whole point is that not every ransomware case starts with phishing -- here, the specific evidence (no phishing indicator anywhere, a known public CVE, an appliance three versions behind current) fits edge-device exploitation far better than an assumption. The brute-force / password-spraying option is wrong because such a case would show a preceding burst of failed logons (Event 4625), which isn't described here -- this is one clean successful login. And deferring vector attribution to post-incident forensics contradicts Reading 2 directly: identifying the actual vector determines the specific remediation (patch the appliance and invalidate its sessions here, rather than retraining a user who did nothing wrong).",
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
        "**Credential access.** Once a specific privileged target is identified, LSASS memory access (T1003.001) harvests whatever credential material is cached on that one host — for example GrantedAccess 0x1FFFFF, PROCESS_ALL_ACCESS, requested against lsass.exe, the pattern covered in this platform's EDR investigation content; many dumpers request narrower masks instead (0x1010, 0x1410, 0x1438 — memory-read plus query rights), so a detection keyed only on 0x1FFFFF misses them. DCSync (T1003.006) goes considerably further: if the affiliate reaches an account holding replication rights (Replicating Directory Changes / Replicating Directory Changes All), they can impersonate a Domain Controller and request every domain account's password hash in a single request, without ever touching LSASS on the DC itself — the Active Directory room already covered exactly why this is so much more efficient than dumping credentials host by host.\n\n" +
        "**Why ransomware affiliates specifically need this, not just 'more access.'** Deploying an encryptor to a handful of hosts one at a time is a slow nuisance a SOC can usually catch and stop. Deploying it to every reachable server and workstation in one coordinated push — via Group Policy, PsExec, or an RMM tool, covered next in Lateral Movement — is what turns an intrusion into a company-wide outage in minutes, and that coordinated push requires exactly the kind of domain-wide administrative credential this stage exists to obtain.",
      checkpoint: {
        question: "Per Reading 4, why is DCSync (T1003.006) a more efficient credential-access method for a ransomware affiliate than dumping LSASS on individual hosts one at a time?",
        options: [
          "It copies NTDS.dit straight off a Domain Controller's disk, so it needs only local admin on any one DC",
          "An account holding replication rights poses as a DC and pulls every domain account's hash in one request",
          "It replays one captured Kerberos ticket to every host, so no password hash ever has to be extracted",
          "It dumps LSASS on the Domain Controller itself, where every account that ever logged on leaves a hash",
        ],
        answer: 1,
        explanation:
          "Reading 4 -- consistent with the Active Directory room -- is specific: an account holding replication rights can request every domain account's hash through AD replication in one shot, far faster than dumping LSASS host after host. Copying NTDS.dit off the DC's disk is a different credential-access technique that needs file access on the DC, not replication rights. Replaying a Kerberos ticket is pass-the-ticket, which reuses one credential rather than harvesting all of them. And the reading stresses that DCSync works without touching LSASS on the DC at all.",
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
            "crowdstrike.ParentProcessName shows cmd.exe, and crowdstrike.CommandLine shows rundll32.exe launched with the argument \"C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 ... full\". Reading the whole event, what is this pattern doing, and why would an affiliate prefer it over dropping a dedicated credential-dumping tool like Mimikatz?",
          options: [
            "A MiniDump-style memory capture, but nothing in the event ties PID 668 to lsass.exe, so it cannot yet count as credential access",
            "rundll32.exe calls comsvcs.dll's MiniDump export to write PID 668's full memory to disk -- a signed Windows DLL, so no dumper is dropped",
            "Windows Error Reporting collecting a crash dump of PID 668 -- the wer-prefixed .tmp name is benign WER output, not a credential dump",
            "comsvcs.dll is injected into lsass.exe to read credentials in place, so no memory dump is written and no tool ever touches the disk",
          ],
          answer: 1,
          explanation:
            "comsvcs.dll ships with Windows and exports a MiniDump function -- calling it via rundll32.exe is a well-documented living-off-the-land dumping technique precisely because no separate, easily-signatured tool is written to disk. The event does tie PID 668 to LSASS: crowdstrike.TargetProcessName is lsass.exe and crowdstrike.TargetProcessId is 668. Genuine WER crash collection is not a cmd.exe-spawned rundll32 calling comsvcs.dll's MiniDump against lsass.exe -- the wer-style name is camouflage. And the command line passes an output path and the word full, so a dump file is written to disk; nothing is injected into LSASS.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.TargetProcessName reads lsass.exe and crowdstrike.GrantedAccess reads 0x1FFFFF. Combining this with the account context in the case description, how should the analyst weigh this access?",
          options: [
            "0x1FFFFF is PROCESS_ALL_ACCESS, the only mask able to read LSASS memory, so a rule keyed on it catches every LSASS dumper",
            "PROCESS_ALL_ACCESS on lsass.exe exposes its cached credentials, and j.reyes's nested Domain Admin rights make the reach domain-wide",
            "Full access to lsass.exe exposes only this host's local SAM accounts, so the blast radius stays limited to WKS-IT-0417 itself",
            "The access is serious, but j.reyes is Tier-1 helpdesk, so anything harvested reaches only the systems helpdesk staff administer",
          ],
          answer: 1,
          explanation:
            "0x1FFFFF is PROCESS_ALL_ACCESS, and against lsass.exe it grants what a credential dumper needs; the context raises the stakes, because j.reyes's token carries indirect Domain Admin rights through group nesting, so this single-host dump is a plausible domain-wide compromise. Reading 4 notes many dumpers use narrower masks (0x1010, 0x1410, 0x1438), so a rule keyed only on 0x1FFFFF misses them. LSASS holds cached credentials of accounts that logged on to the host, including domain accounts -- not just local SAM accounts. And judging reach by the Tier-1 job title is exactly the trap the group-nesting issue in the context warns about.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.CommandLine sends the memory dump to C:\\ProgramData\\Adobe\\ARM\\wer4A21.tmp -- a folder and naming style that resemble Adobe's updater and Windows crash-report artifacts. Why would an affiliate choose this location and name for the dump file?",
          options: [
            "Because ProgramData is writable without admin rights, so it was simply the first place j.reyes's token could write the file",
            "To blend in: a wer-named .tmp in an Adobe updater folder looks like routine crash output to anyone skimming the directory",
            "To stage the dump beside Adobe updater traffic, so it can later leave the host disguised as an ARM update download",
            "Because Windows purges .tmp files at the next reboot, deleting the dump before forensic collection can reach it",
          ],
          answer: 1,
          explanation:
            "This is a masquerading choice -- MiniDump writes wherever the command line says, and a wer-style .tmp in a vendor folder is a file a defender is unlikely to scrutinise one by one. Writability does not explain it: j.reyes's token carries Domain Admin rights, so many locations were writable, and the Adobe folder plus WER-style name are deliberate. The dump's location says nothing about how it leaves the host; exfiltration is a later, separate stage. And Windows does not purge .tmp files at reboot because of their extension -- the file stays until something deletes it.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.PatternDispositionDescription reads \"Detected, no action taken,\" meaning Falcon only observed this LSASS access rather than stopping it. Given everything in this finding -- the LOLBin technique, the masquerading dump path, and j.reyes's indirect Domain Admin rights -- what should the analyst do immediately?",
          options: [
            "Isolate and reimage WKS-IT-0417, since the dump file and the affiliate's foothold both live on that one workstation",
            "Treat every credential j.reyes's token can reach as compromised: start domain-wide rotation and scoping, and escalate now",
            "Watch j.reyes's account for a second alert first, since \"Detected, no action taken\" means Falcon rated the access low-risk",
            "Reset only j.reyes's password and revoke his sessions, since the dump ran under his account and that closes the exposure",
          ],
          answer: 1,
          explanation:
            "\"Detected, no action taken\" means the dump was never stopped -- it raises urgency rather than lowering it, so waiting for a second alert hands the affiliate time to use what was taken. Isolating the workstation is reasonable, but treating a reimage as the remediation ignores that the dumped credentials are now usable from anywhere. Resetting only j.reyes's password misses that an LSASS dump also captures other accounts cached on the host. Given the domain-wide reach of this token, the right response is domain-wide rotation, scoping and immediate escalation.",
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
          "The 7045 service name: admins' PsExec creates PSEXESVC, so a renamed service is the reliable sign of an attacker",
          "One account repeating type 3 logon then PSEXESVC across many hosts in minutes, from an unexpected source or hour",
          "The logon type: admins run PsExec from inside RDP sessions (type 10), while an attacker's PsExec shows type 3",
          "WmiPrvSE.exe as the parent of the remote command, which PsExec produces only when an attacker is driving it",
        ],
        answer: 1,
        explanation:
          "Reading 5 was explicit that PsExec is legitimate and used constantly by IT -- the tell is the pattern (repetition across hosts in a short window, unexpected account/source/timing), not the tool. A renamed service is one possible attacker choice, but the default PSEXESVC name proves nothing either way, so the service name alone cannot separate admin from attacker. PsExec's target-side logon is type 3 whoever runs it; type 10 is the RDP logon on a different host. And WmiPrvSE.exe as the parent is the WMI lateral-movement giveaway, not something PsExec produces.",
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
        "Reconnaissance rather than lateral movement -- a type 3 logon plus a service creation only enumerates hosts for later targeting, and no attacker code has actually executed on either server yet",
        "A single administrator managing two servers -- logon type 3 is routine for remote administration, and two hosts nine minutes apart from one source IP fits ordinary patching cadence",
        "PsExec lateral movement with the j.reyes credential -- the same account and source IP repeating the type 3 logon then PSEXESVC pattern across servers, so scope every host it touched tonight",
        "The ransomware encryption stage already in progress -- a PSEXESVC service on a second server means the encryptor is being pushed fleet-wide, so this should be handled as detonation",
      ],
      answer: 2,
      explanation:
        "PsExec is legitimate, but the identical, repeating pattern across two hosts within nine minutes -- from the exact account this room's log analysis already flagged as compromised and carrying broad reach -- is the lateral-movement signature Reading 5 described, not routine single-admin activity. Reading it as the encryption stage already in progress wrongly conflates lateral movement (spreading access) with the later, distinct Impact stage covered further on in this room -- PsExec here is being used to move and stage, not to encrypt.",
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
        { id: "dcsync", left: "An account that already holds replication rights asks a Domain Controller to replicate every password hash at once", right: "T1003.006 -- DCSync" },
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
        { id: "evasion", text: "Defense Evasion -- with the newly gained privileges, EDR/AV is stopped or excluded on the hosts the affiliate needs, so the bulk transfer and encryptor that follow run unseen" },
        { id: "exfil", text: "Exfiltration -- staged, compressed data is pushed out via rclone or a similar tool, before encryption starts" },
        { id: "impact", text: "Impact and Extortion -- shadow copies are deleted and logs cleared, then the encryptor runs fleet-wide and the ransom note appears, referencing already-published stolen data" },
      ],
      correct_order: ["init", "exec", "persist", "discover", "cred", "lateral", "evasion", "exfil", "impact"],
      explanation:
        "Each stage depends on what the previous one produced: execution needs the foothold Initial Access delivered; Persistence protects that foothold before the affiliate risks losing it to a reboot; Discovery and Credential Access together are what make fleet-wide Lateral Movement possible in the first place; disabling or excluding EDR needs the privileges the earlier stages won, and it comes before the bulk transfer and the encryptor so that those noisy stages run unseen; shadow-copy deletion (ATT&CK files it as T1490, an Impact technique) and log clearing are deliberately left to the final stage, run shortly before mass file activity begins as Reading 6 describes, because deleting backups early would itself be a loud alarm; and -- as Reading 7 covers next -- Exfiltration now routinely runs before Impact rather than alongside it, because a well-organized affiliate wants the leverage fully banked before risking the detection an obvious mass-encryption event almost guarantees.",
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
        question: "Per Reading 7, why is the exfiltration-staging window often the highest-value point for a SOC to intervene in a current-model intrusion?",
        options: [
          "Staging comes before credential access, so cutting it off removes the affiliate's route to domain-wide privileges",
          "It is often the last point where acting changes the outcome: the stolen data, the attacker's leverage, has not left yet",
          "Once the data is out, the leak threat is moot anyway as long as clean, tested backups let the victim restore and move on",
          "Many campaigns now skip encryption entirely, so staging is usually the only stage that produces any telemetry",
        ],
        answer: 1,
        explanation:
          "Reading 7 was explicit: encryption's damage to availability is largely fixed once it starts, but exfiltration caught during staging can stop the double-extortion leverage from ever reaching the attacker. In the current model, staging comes after credential access and lateral movement, not before. Reading 1 explains that backups do nothing against a leak threat -- that is why double extortion exists. And the 'encryption-optional' trend means some campaigns skip encryption; it does not make staging the only stage with telemetry -- this room shows detections at nearly every stage.",
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
            "crowdstrike.FilePath shows the transfer tool running from C:\\Users\\Public\\rclone.exe, and crowdstrike.ParentProcessName is cmd.exe. What should these details make the analyst check first?",
          options: [
            "Nothing further on the path: rclone is a known exfiltration tool, so its mere presence on a server already confirms the compromise",
            "Why a transfer tool runs from a public folder via cmd.exe on a server with no documented need -- location and launch are the signal",
            "Whether the SHA256 matches a known-bad hash, since an unmodified rclone build is benign wherever it happens to be launched",
            "Whether j.reyes appears on rclone's software-approval list, since an approved tool run by an approved user is routine",
          ],
          answer: 1,
          explanation:
            "rclone is legitimate, widely-used software -- this room's analyst_choice task shows a benign use of the identical tool -- so the tool's name alone confirms nothing. What matters is the unusual location (a generic Public folder, not an installed-software path) and the manual cmd.exe launch on a server whose only documented transfer job is something else. A clean hash only says the binary is genuine rclone; a genuine tool can still carry stolen data. And an approval list for the user does not authorise this specific transfer: an approved admin running rclone outside any ticket is still unexplained activity.",
          xp: 30,
        },
        {
          question:
            "Read crowdstrike.CommandLine in the event above. What does it reveal about the scope and intent of the transfer?",
          options: [
            "A routine sync job: copy only adds files missing at the destination, and -q merely hides progress, as scheduled backups do",
            "A targeted pull of the Finance-Q4 share, run quietly with 16 parallel transfers, to a remote defined in a config left in Public",
            "Limited impact: copy leaves the source files intact, so nothing is lost and this ranks below a move or sync that deletes data",
            "A Google Drive backup: the gdrive-sync remote name shows an IT-built integration, so only the change ticket needs checking",
          ],
          answer: 1,
          explanation:
            "Read closely, the command line shows a specific high-value source (the Finance-Q4 share), quiet output (-q), 16 parallel transfers for speed, and a remote defined in rc.conf sitting in C:\\Users\\Public -- not a managed config path. Calling it a routine sync ignores that the only documented backup on this server is the Veeam job writing on-premises. Copy leaving the source intact is exactly what exfiltration wants: the damage is the stolen copy, not lost files. And a friendly-sounding remote name like gdrive-sync proves nothing; the remote is whatever the dropped config file says it is.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.UserName on this detection is NEXACORP\\j.reyes. How should the analyst relate this finding to the rest of tonight's activity?",
          options: [
            "As a separate case: the account matches, but a different host and a two-hour gap point to unrelated activity",
            "As the same intrusion: the credential dumped on WKS-IT-0417 two hours ago is plausibly now driving this exfiltration",
            "Link them only if j.reyes logged on to SRV-FILES-04 interactively, since stolen credentials cannot run remote commands",
            "As insider activity: one named user acting on two hosts in one night points to j.reyes himself, not stolen credentials",
          ],
          answer: 1,
          explanation:
            "This is the account whose token was dumped on WKS-IT-0417 two hours earlier and carries indirect Domain Admin rights -- its next use, on a high-value file server, is the thread connecting credential theft to exfiltration. Splitting them by host and time is the sibling-alert mistake this platform's EDR content warned against. Stolen credentials run remote commands all the time -- PsExec and WMI in Reading 5 do exactly that over network logons. And reading this as the user himself ignores that his credentials were just dumped at 02:47 by a LOLBin on his workstation; the account name says whose credential was used, not who typed.",
          xp: 30,
        },
        {
          question:
            "it_verify_result reads \"unverified,\" and it_verify_message notes the file server's only documented backup tool is the nightly Veeam Agent job -- not rclone. Combined with everything else in this finding, what should the analyst do right now?",
          options: [
            "Disable j.reyes and reset his password, then let the transfer run under watch to measure exactly what is being taken",
            "Cut SRV-FILES-04's route to the external destination and alert IR now, as the same intrusion -- encryption may never come",
            "Escalate to IR but leave network access alone until encryption starts, since containing now would warn the affiliate early",
            "Ask IT to raise a retroactive change ticket for the job, since \"unverified\" only means nobody has checked the queue yet",
          ],
          answer: 1,
          explanation:
            "This is the highest-value moment Reading 7 described: staging caught before encryption is where the outcome can still change, so the outbound path is cut now and IR is alerted. Letting the transfer run to measure it hands the attacker the leverage you are trying to deny -- and disabling the account does not stop an rclone process that is already running. Holding containment until encryption starts throws away the window, and Reading 7 says some affiliates skip encryption altogether. And it_verify_message already shows the check was done: no ticket exists and the only documented backup is Veeam, so a retroactive ticket would paper over an unexplained transfer.",
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
        "During the post-incident retro-hunt, the team re-reviews every older Falcon Exfiltration-to-Cloud-Storage detection -- the technique family of the SRV-FILES-04 staging finding confirmed as a true positive earlier in this room. One, from 2 March, fired on SRV-ARCHIVE-02. Before deciding, the analyst opened the config file named by --config in the command line: the sharepoint-nexacorp remote is a OneDrive-type remote bound to the nexacorp.sharepoint.com tenant that NexaCorp IT administers. Review the detection, including the change-management lookup (it_verify) shown under the log, and decide whether this one is a true positive or a false positive.",
      event: migrationRcloneEvent,
      correct_verdict: "false_positive",
      explanation:
        "crowdstrike.FilePath is C:\\Program Files\\RecordsMigration\\rclone.exe -- an installed-software location, not a generic Public folder. crowdstrike.ParentProcessName is MigrationScheduler.exe, a scheduler process, not cmd.exe launched by hand. The remote's name alone would prove nothing -- a friendly name is exactly the trap from the SRV-FILES-04 finding -- but the config the analyst opened binds sharepoint-nexacorp to NexaCorp's own administered tenant, nexacorp.sharepoint.com. crowdstrike.UserName is svc-migrate, a service account, not the privileged human account flagged in the active incident. And it_verify_result is confirmed: change ticket CHG-40881 authorises this migration from this host to the company's SharePoint tenant, on this nightly schedule, with svc-migrate as the documented account.",
      fp_trap:
        "This detection uses the identical technique family -- and the identical tool, rclone -- as the confirmed true-positive exfiltration finding earlier in this room, which makes escalating it on reflex extremely tempting. But the specific fields tell two very different stories: proper install location vs. a generic Public folder, a scheduler parent vs. manual cmd.exe launch, a destination verified in the config as the company's own tenant vs. an unverified remote from a config dropped in a Public folder, a documented migration service account vs. a privileged account already flagged in an active incident, and a confirmed change ticket vs. no ticket at all. Escalating every rclone-to-cloud pattern without checking these fields either buries the SOC in noise on every legitimate backup or migration job, or -- just as dangerously -- teaches the team to stop reading past the tool's name entirely, which is exactly the habit that would let a real exfiltration attempt hide behind a routine-sounding process.",
      xp: 35,
    },
    // ── Reading 8: Impact, extortion, and the full-chain playbook ────────────
    {
      type: "reading" as const,
      id: "rw-r8",
      heading: "Impact and Extortion: Encryption Mechanics and the Full-Chain Playbook",
      content:
        "**How the encryption actually works (T1486).** Production ransomware doesn't encrypt with one slow, crackable algorithm — it uses a fast symmetric cipher (commonly AES or ChaCha20) to encrypt each file's contents quickly at scale, then wraps that per-file or per-host symmetric key with an asymmetric public key (RSA or ECC) baked into the encryptor binary at build time. The matching private key never touches the victim's environment at all — it exists only on the attacker's own infrastructure. This is exactly why 'just recover the key from memory' almost never works at any real scale, and why free public decryptors are genuinely rare: they normally exist only because researchers found an actual implementation flaw in one specific family's build, or because law enforcement seized or obtained the operators' private keys (as in the Hive and LockBit takedowns) — not because the underlying cryptography itself was broken.\n\n" +
        "**What the moment of impact looks like in telemetry.** A mass, rapid file-modification and rename event from a single process across an enormous number of files in a short window, almost always paired with a new, previously-unseen extension appended to every file it touches, and a note file dropped into common, highly visible locations. Modern EDR platforms specifically watch for this rename-rate spike as a distinct, high-confidence behavioral signature — independent of the specific binary's hash or file name, which is exactly why disguising the binary's name (as this room's own case study shows) slows detection down but does not defeat it.\n\n" +
        "**The extortion note and what follows it.** The note directs the victim toward a negotiation channel — often a Tor-hosted chat portal — and, in a double-extortion case, references a leak site where a sample of the stolen data is already published as proof, with a countdown before the rest goes up. Some groups add further pressure on top of this: contacting the victim's own customers or regulators directly, or threatening a denial-of-service against public-facing systems — a pattern industry reporting sometimes calls triple extortion.\n\n" +
        "**The full-chain playbook — what the SOC actually does at every stage, not just at the end** — is laid out stage by stage in the table below this reading: for each stage, the detection point a SOC actually sees and the analyst action that goes with it.\n\n" +
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
            "Only the path: wuauclt32.exe is the 32-bit Windows Update client, which belongs under SysWOW64 rather than Windows\\Temp",
            "The real client is wuauclt.exe in System32; a near-match name running from Windows\\Temp is masquerading in name and location",
            "Only the account: the name is genuine, but Windows Update runs as the signed-in user, so a SYSTEM-run copy is the anomaly",
            "Neither is decisive: Windows Update stages its payloads under Windows\\Temp, so only a hash lookup can settle this one",
          ],
          answer: 1,
          explanation:
            "This is textbook masquerading: a name close enough to a real system process to pass a quick glance (wuauclt.exe vs. wuauclt32.exe), combined with a location -- C:\\Windows\\Temp -- the genuine client never runs from; the two together are the tell. There is no 32-bit wuauclt32.exe -- the 32-bit copy under SysWOW64 keeps the same wuauclt.exe name, so the name itself is wrong, not just the path. Windows Update runs under the system's update service, so SYSTEM is expected and the account is not the anomaly here. And the genuine client does not run from Windows\\Temp; the name and path already answer the question before any hash lookup.",
          xp: 30,
        },
        {
          question:
            "crowdstrike.CommandLine reads: wuauclt32.exe --path C:\\ --ext .a8f2e91c --note RESTORE-FILES-a8f2e91c.txt --skip C:\\Windows,C:\\ProgramData,C:\\$Recycle.Bin --threads 24. What do these specific arguments reveal about the tooling and the affiliate's intent?",
          options: [
            "A wiper: the random-looking extension shows files are being overwritten, and --skip only delays damage to the boot volume",
            "A configurable encryptor: all of C:\\, a fixed extension and note, system folders skipped so the host still boots to show it",
            "A staging tool: --path C:\\ with 24 threads is bulk collection of files for exfiltration before the real encryptor is pushed",
            "A narrowly targeted encryptor: the --skip list shows it touches only the user data the affiliate already exfiltrated",
          ],
          answer: 1,
          explanation:
            "Encryptors are commonly built with exactly this configurability -- target path, extension, note filename, and directories to skip. Skipping system directories is functional: a host that still boots and shows the note serves the extortion goal, which is also what separates ransomware from a wiper -- a wiper has no reason to drop a RESTORE-FILES note or protect the OS. Staging comes before Impact and does not add a new extension or drop a note -- both of which this command line does. And --skip lists folders to avoid, not data to target: everything else on C:\\ is in scope, exfiltrated or not.",
          xp: 35,
        },
        {
          question:
            "crowdstrike.PatternDispositionDescription reads \"Detected, kill process\" -- this specific host was actually blocked, unlike the earlier findings in this room. Given the context (sixty-one detections in five minutes, a scheduled task pushed to more than 140 hosts), what does this one block tell the analyst, and what comes next?",
          options: [
            "The encryptor is now detected fleet-wide, so the other detections were very likely blocked too and the push is largely contained",
            "The scheduled task is the root cause, so deleting wuauclt32Check from all 140 hosts comes before checking any per-host outcomes",
            "Protection varies by host, so this block says nothing about the rest; next, find which of the ~140 targeted hosts were not blocked",
            "This host is safe and can leave scope, since a kill-process disposition means the encryptor never touched any file on it",
          ],
          answer: 2,
          explanation:
            "Reading 6 established that tamper protection and tooling state vary by host, so one successful block says nothing about the other targeted hosts -- the next step is finding which of them were not protected. A detection firing does not mean a block: the earlier findings in this room were \"Detected, no action taken\", so assuming the rest were blocked is unsafe. The task fired at 07:00 and the encryptors are already running, so deleting it now does not stop active encryption on unprotected hosts -- outcome-checking and isolation come first. And kill-process stops the binary when the detection fires, which can be after some files were already encrypted, so this host still needs checking.",
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
        "Open a negotiation channel through the leak-site portal in parallel with isolation, since the SOC holds the technical detail needed to judge the attacker's proof and can buy the business time",
        "Isolate hosts with active or attempted encryption, scope hit vs. merely targeted hosts, preserve evidence, and give IR, legal and executives the blast radius, exfiltration facts and IOCs",
        "Hard power-off every host showing encryption plus the file servers and domain controllers, then rebuild everything from backup, since a full shutdown stops the spread fastest and evidence can be rebuilt from logs",
        "Start restoring the already-encrypted hosts from backup first, since recovery time drives the business impact and containment of the remaining hosts can follow once critical services are running again",
      ],
      answer: 1,
      explanation:
        "Isolating, scoping, preserving evidence and briefing IR/legal/executives matches Reading 8's playbook directly: contain the still-active spread, scope accurately, preserve evidence, and deliver facts -- not a payment decision -- to the people actually authorized to make that call. Opening a negotiation channel hands the SOC a decision and a level of external contact it should never have. Hard power-off of everything is disproportionate: powering off hosts destroys volatile evidence (memory, live connections) and the domain controllers needed for recovery, without scoping which hosts were actually affected. Restoring encrypted hosts first gets the order wrong: restoring onto a network where the encryptor is still spreading just feeds it new victims, and stopping the spread to hosts NOT yet encrypted is the highest-value action still available.",
      xp: 30,
    },
    // ── Flag ───────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "rw-f1",
      prompt:
        "An HR user on WKS-HR-0233 reports that C:\\Users\\hr.user\\Documents\\budget.xlsx “changed its name” this morning. Using the encryptor detection on that host, what is the file's full new name? (File name only, no folder path.)",
      answer: "budget.xlsx.a8f2e91c",
      hint: "Check whether that folder is excluded, then recall from Reading 8 whether the new extension replaces the old one or is added to it.",
      xp: 25,
    },
  ],
};

export const roomsBatch33 = [ransomwareLifecycleRoom];
