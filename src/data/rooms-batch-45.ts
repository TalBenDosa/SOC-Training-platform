/**
 * Learning Rooms — Batch 45
 *
 * Closes a P1 coverage gap: four MITRE ATT&CK techniques that describe the
 * full data-theft pipeline — T1039 (Data from Network Shared Drive), T1074.001
 * (Data Staged: Local Data Staging), T1560.001 (Archive Collected Data:
 * Archive via Utility), and T1052.001 (Exfiltration Over Physical Medium:
 * USB) — are all PRACTISED repeatedly across this platform's live SOC feed
 * and scenario library (see src/lib/sim/scenario-packs/insiderDlpUsbCloud.ts
 * for one such practised case) but were never taught end to end as their own
 * ATT&CK technique chain in any room or lesson. This room is the theory
 * companion; it deliberately does NOT re-teach DLP-as-a-tool (see the
 * existing "dlp-fundamentals" room) or insider-threat motive/ethics (see the
 * existing "insider-threat-and-data-exfiltration" lesson) — it follows the
 * pure ATTACKER technique chain: Collection at the share -> local staging ->
 * archiving -> the actual Exfiltration channel (USB, cloud storage, or an
 * alternative protocol).
 *
 * All four techniques verified against MITRE ATT&CK's own technique pages
 * (attack.mitre.org) at write time, including tactic assignment: T1039,
 * T1074.001, and T1560.001 are ALL Collection (TA0009) even though staging
 * and archiving intuitively feel like "the theft" -- only T1052.001,
 * T1567.002, and T1048 are Exfiltration (TA0010), the technique that actually
 * moves data off the compromised host.
 *
 * Rooms in this batch:
 *  1. data-staging-exfiltration-channels
 *
 * SOURCES consulted directly for this content:
 *  - MITRE ATT&CK T1074.001, Data Staged: Local Data Staging (attack.mitre.org/techniques/T1074/001/)
 *  - MITRE ATT&CK T1039, Data from Network Shared Drive (attack.mitre.org/techniques/T1039/)
 *  - MITRE ATT&CK T1560.001, Archive Collected Data: Archive via Utility (attack.mitre.org/techniques/T1560/001/)
 *  - MITRE ATT&CK T1052.001, Exfiltration Over Physical Medium: USB (attack.mitre.org/techniques/T1052/001/)
 *  - MITRE ATT&CK T1567.002, Exfiltration Over Web Service: Exfiltration to Cloud Storage (attack.mitre.org/techniques/T1567/002/)
 *  - MITRE ATT&CK T1048, Exfiltration Over Alternative Protocol (attack.mitre.org/techniques/T1048/)
 *  - MITRE ATT&CK T1030, Data Transfer Size Limits (attack.mitre.org/techniques/T1030/)
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Data Staging & Exfiltration Channels
// ===========================================================================

// Log-analysis event: the exfiltration channel itself (T1567.002) as seen by
// a firewall -- deliberately non-EDR, so no EDR-console hash dependency.
const megaUploadEvent: TelemetryEvent = {
  "id": "dsx-fw-mega-upload-001",
  "ts": "2026-07-22T23:41:17.000Z",
  "source": "firewall",
  "vendor": "FortiGate",
  "event_type": "net_connection",
  "severity": "high",
  "mitre_technique": "T1567.002",
  "mitre_tactic": "Exfiltration",
  "hostname": "WKS-LAW-214",
  "user_email": "m.alvarez@meridianlawgroup.com",
  "user_title": "Paralegal",
  "src_ip": "10.50.12.214",
  "dst_ip": "31.216.148.28",
  "dst_port": 443,
  "protocol": "tcp",
  "description": "FortiGate logged an allowed outbound HTTPS session from WKS-LAW-214 to mega.nz at 23:41, roughly two hours after normal business hours ended, carrying a large volume of outbound data with very little returned.",
  "raw": {
    "data.type": "traffic",
    "data.subtype": "forward",
    "data.logid": "0000000013",
    "data.level": "notice",
    "data.vd": "root",
    "data.action": "accept",
    "data.srcip": "10.50.12.214",
    "data.srcport": 51882,
    "data.srcintf": "internal",
    "data.dstip": "31.216.148.28",
    "data.dstport": 443,
    "data.dstintf": "wan1",
    "data.dstname": "mega.nz",
    "data.dstuser": "m.alvarez",
    "data.proto": 6,
    "data.service": "HTTPS",
    "data.sentbyte": 796305664,
    "data.rcvdbyte": 88240,
    "data.duration": 187,
    "data.srccountry": "Reserved",
    "data.dstcountry": "New Zealand",
    "data.app": "MEGA",
    "data.appcat": "Cloud.IT",
    "data.apprisk": "elevated",
    "data.logdesc": "Forward traffic accepted",
    "data.msg": "Forward traffic accepted",
    "data.eventtime": 1785544877,
    "data.policyid": 14,
    "data.policyname": "Outbound_Internet_Default"
  }
};

// Analyst-choice control case: a legitimate, ticketed, service-account backup
// job walking the identical shape -- resolved via it_verify_result, never via
// an invented raw field.
const veeamBackupEvent: TelemetryEvent = {
  "id": "dsx-fw-veeam-backup-001",
  "ts": "2026-07-23T02:00:04.000Z",
  "source": "firewall",
  "vendor": "FortiGate",
  "event_type": "net_connection",
  "severity": "informational",
  "hostname": "BKP-VEEAM-01",
  "user_title": "Backup Service Account",
  "src_ip": "10.50.12.60",
  "dst_ip": "20.150.66.201",
  "dst_port": 443,
  "protocol": "tcp",
  "description": "FortiGate logged an allowed outbound HTTPS session from the backup server BKP-VEEAM-01 to the organisation's own Azure Blob Storage account at 02:00, carrying a large nightly volume — matching the identical time and destination seen on this host for the past six months.",
  "it_verify_result": "confirmed",
  "it_verify_message": "IT confirms BKP-VEEAM-01 runs the organisation's Veeam Backup and Replication job under change ticket CHG-2026-1187, executed by the dedicated service account svc-veeam-backup, targeting meridianlawbackups.blob.core.windows.net — the firm's own Azure Blob Storage backup container, not a third-party or personal destination. The job has run at 02:00 nightly, at a consistent volume, for the past six months with no exceptions.",
  "raw": {
    "data.type": "traffic",
    "data.subtype": "forward",
    "data.logid": "0000000013",
    "data.level": "notice",
    "data.vd": "root",
    "data.action": "accept",
    "data.srcip": "10.50.12.60",
    "data.srcport": 49221,
    "data.srcintf": "internal",
    "data.dstip": "20.150.66.201",
    "data.dstport": 443,
    "data.dstintf": "wan1",
    "data.dstname": "meridianlawbackups.blob.core.windows.net",
    "data.dstuser": "svc-veeam-backup",
    "data.proto": 6,
    "data.service": "HTTPS",
    "data.sentbyte": 12483920640,
    "data.rcvdbyte": 498112,
    "data.duration": 2640,
    "data.srccountry": "Reserved",
    "data.dstcountry": "United States",
    "data.app": "MS-Azure-Storage",
    "data.appcat": "Cloud.IT",
    "data.apprisk": "low",
    "data.logdesc": "Forward traffic accepted",
    "data.msg": "Forward traffic accepted",
    "data.eventtime": 1785549604,
    "data.policyid": 22,
    "data.policyname": "Backup_Server_Egress"
  }
};

const dataStagingExfilRoom = {
  "id": "data-staging-exfiltration-channels",
  "title": "Data Staging & Exfiltration Channels: From Collection to Egress",
  "description": "Follow the exact ATT&CK technique chain a real intrusion walks once an attacker has a foothold and a target: reaching into a network share (T1039), consolidating the target files on the local host (T1074.001), packaging them with a password-protected archive utility (T1560.001), and finally moving them out over USB, cloud storage, or an alternative protocol (T1052.001, T1567.002, T1048, T1030). Learn why staging and archiving both stay in the Collection tactic while only the final channel is Exfiltration, read real FortiGate firewall telemetry for a cloud-storage exfiltration channel, and learn to tell that chain apart from an enterprise backup job that walks an almost identical shape every single night.",
  "difficulty": "intermediate",
  "category": "Threat Detection",
  "estimatedMinutes": 65,
  "xp": 265,
  "icon": "📦",
  "prerequisites": [
    "dlp-fundamentals",
    "firewall-log-analysis",
    "endpoint-security-fundamentals"
  ],
  "tasks": [
    {
      "type": "reading" as const,
      "id": "dsx-r0",
      "heading": "The Chain: Collection, Staging, Archiving, and Exfiltration",
      "content": "Picture a burglar inside a house at night. They do not carry the silverware, the jewellery, and the electronics out one item at a time through a window — that takes too many trips and too much time exposed. Instead they gather everything into one bag by the back door, and only then make the single trip outside. Data theft from a compromised network follows the identical logic, and MITRE ATT&CK — the industry-standard catalogue of real adversary techniques, organised into TACTICS (the attacker's goal, such as Collection or Exfiltration) and TECHNIQUES (the specific method used to achieve that goal) — gives each stage of that logic its own technique ID, because each stage produces different telemetry and needs a different detection approach.\n\nThis room walks the exact chain a real intrusion follows once an attacker already has a foothold and a target in mind, stage by stage: first COLLECTION — reaching into a network share to read what is there (T1039, Data from Network Shared Drive) and then consolidating the interesting parts onto one host (T1074.001, Local Data Staging) — then still-Collection PACKAGING — compressing and usually password-protecting that staged data with an archive utility (T1560.001, Archive via Utility) — and only then EXFILTRATION, the step that actually moves the packaged data off the host and out of the organisation's control, whether over a physical medium like a USB drive (T1052.001), to a cloud storage service (T1567.002), or over some other protocol entirely (T1048), sometimes deliberately split into small pieces to dodge volume-based alarms (T1030).\n\nOne fact surprises almost every new analyst enough to be worth stating up front: staging AND archiving both still belong to the COLLECTION tactic, not Exfiltration, even though compressing a password-protected archive feels like 'the theft.' Nothing has left the host yet at that point — the data is simply organised and packaged. The tactic only changes to Exfiltration at the technique that actually moves bytes off the compromised system. Getting this distinction right matters for more than trivia: it is what lets an analyst recognise that seeing a large new archive appear on a host, even with no outbound traffic yet, is itself a genuine finding worth acting on before the exfiltration step ever happens.\n\nTwo companion pieces of this curriculum cover adjacent ground and are worth knowing about rather than re-reading here. The 'Data Loss Prevention (DLP) for SOC Analysts' room covers DLP as a TOOL in real depth — its three channels, its policy engine, its confidence scoring, and how to triage a DLP alert; this room instead follows the ATTACKER'S technique chain that DLP is trying to catch. The 'Insider Threat and Data Exfiltration' lesson covers the human side — motive, the CERT crime taxonomy, and the ethics of investigating a named employee; this room instead assumes nothing about who is behind the keyboard (an external intruder with stolen credentials fits the chain below exactly as well as a malicious insider does) and stays purely on the technical mechanics of how data physically moves from a share to outside the perimeter.\n\n| Stage | Technique | ATT&CK Tactic |\n| --- | --- | --- |\n| Reach into the share | T1039 — Data from Network Shared Drive | Collection |\n| Consolidate locally | T1074.001 — Data Staged: Local Data Staging | Collection |\n| Package for transport | T1560.001 — Archive Collected Data: Archive via Utility | Collection |\n| Move it off the host | T1052.001 (USB) / T1567.002 (cloud) / T1048 (alt. protocol) | Exfiltration |\n\nBy the end of this room you will be able to name the correct technique ID and tactic for every stage of this chain, read the real telemetry each stage leaves behind, and — critically — tell a genuine attack chain apart from an enterprise backup job that walks an almost identical shape every single night.",
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "dsx-r1",
      "heading": "T1039 — Collection at the Share",
      "content": "T1039, Data from Network Shared Drive, sits under the COLLECTION tactic (TA0009) and covers exactly what its name says: an attacker with network access — whether from a compromised workstation, a stolen VPN session, or a foothold on another server — reaches into a file share the compromised account can legitimately reach, and reads what interests them. Network shares are an obvious target precisely because they already concentrate an organisation's most useful files in one place: a legal firm's client-matter share, a finance team's shared drive, an engineering team's source-control mirror. An attacker rarely needs to compromise a file server directly; they only need one account with legitimate read access to the share, which describes almost every regular employee at least once.\n\nMITRE ATT&CK documents this technique as a genuinely common and low-effort step for real intrusions, most often carried out with tools already built into the operating system — exactly the kind of 'living off the land' behaviour that makes it blend into ordinary activity. The Chinese state-sponsored group menuPass has been documented mounting shares with the built-in Windows command net use and then copying files off them with Robocopy, a signed Microsoft utility present on every modern Windows install and used constantly for entirely legitimate purposes. Malware families take a more automated approach: BADNEWS crawls every mapped drive it can reach looking specifically for files ending in .doc, .docx, .pdf, .ppt, .pptx, and .txt; CosmicDuke works from a predefined list of file extensions and keywords to decide what is worth stealing; and the Gamaredon Group's tooling specifically targets Microsoft Office documents sitting on mapped network drives. APT28 has also been documented collecting files directly from network shares as a routine step in its intrusions.\n\n### What This Looks Like in Telemetry\n\nWindows can audit this precisely through Event ID 5145 (A network share object was checked to see whether the client can be granted desired access) — the detailed file-share-access event, distinct from the simpler 5140 (a share was accessed at all). A single 5145 record carries the requesting account, the source IP, the share name, the specific file or folder path relative to the share, and the access mask requested. One record on its own is unremarkable — file shares exist to be read. What turns this into a lead is volume and pattern: the same account generating hundreds of 5145 records against one share in a span of minutes, especially outside that account's normal working pattern, or a workstation-tier account reaching for the ADMIN$ or C$ administrative shares it has never touched before.\n\n### The Analyst's Question\n\nThe question worth asking is never 'did this account access the share' — nearly every account legitimately does. It is: does the VOLUME, the SCOPE, and the TIMING of this access match what this specific account normally does on this specific share? A paralegal reading a handful of files from their own assigned case folders across a workday is unremarkable. The same paralegal's account reading hundreds of files across every case folder on the share within an eight-minute window is the pattern worth pulling on — and it is the opening move of the chain this room follows for the rest of its length.",
      "checkpoint": {
        "question": "Which Windows Event ID gives the DETAILED record of a file-share access — the specific file path, access mask, and requesting account — as opposed to just confirming a share was touched at all?",
        "options": [
          "Event ID 5140 — A network share object was accessed, without the per-file path or access-mask detail 5145 provides",
          "Event ID 5145 — A network share object was checked to see whether the client can be granted desired access",
          "Event ID 4624 — An account was successfully logged on, which says nothing about which files were touched afterward",
          "Event ID 4769 — A Kerberos service-ticket request, unrelated to any file-share access at all"
        ],
        "answer": 1,
        "explanation": "5145 is the DETAILED file-share-auditing event — it carries the specific share name, relative file/folder path, and access mask requested, which is what lets an analyst see WHAT was touched, not just THAT the share was touched. 5140 only confirms a share object was accessed, with far less detail. 4624 is a general logon event and carries nothing about file-share activity. 4769 is a Kerberos service-ticket request, relevant to authentication (and to Kerberoasting elsewhere in this curriculum), not file-share access."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "dsx-r2",
      "heading": "T1074.001 — Staging: Consolidating on the Local Host",
      "content": "Once an attacker has identified the files worth taking, walking back to the network share for every single file — especially a share the account does not normally use this heavily — is slow and leaves a long trail of 5145 records. T1074.001, Data Staged: Local Data Staging, is MITRE ATT&CK's name for the far more efficient next move: consolidating the target data into one central location on a host BEFORE exfiltration, so the actual removal step is one clean operation instead of hundreds of scattered ones. Like T1039, this technique still belongs to the COLLECTION tactic (TA0009) — the data has moved from the share to a folder on a computer the attacker already controls, but it has not yet left the organisation's network at all.\n\nATT&CK's own documentation names common shell utilities — cmd and bash — as the everyday tools for this step, simply because copying files into a folder needs nothing more exotic than that. Real malware families demonstrate a range of staging approaches: PlugX collects and stages victim files ahead of exfiltration; Kazuar stages command output specifically before it gets exfiltrated; QakBot stores stolen emails in local folders before moving them onward; and DarkWatchman takes an unusually clever approach, staging its collected data directly inside the Windows Registry rather than in a file at all — a choice that specifically defeats any monitoring built only to watch file-system write events.\n\n### Where Attackers Stage Data\n\nThe locations that recur constantly across real intrusions are, unsurprisingly, the folders every user account can write to without needing elevated privileges: C:\\Windows\\Temp, the current user's own %TEMP% environment variable (which expands to a path like C:\\Users\\<username>\\AppData\\Local\\Temp), C:\\ProgramData, and on Linux and macOS hosts simply /tmp. None of these paths require administrator rights to write into, which is exactly why they are chosen — staging should not itself require a privilege escalation the attacker may not yet have.\n\nA worked example of what this actually looks like as a command line, using the same signed, built-in Robocopy utility mentioned in the previous reading:\n\nROBOCOPY.EXE \"\\\\FS-LAW01\\ClientMatters$\\Litigation\" \"C:\\ProgramData\\SysHelper\\stage\" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL\n\nRead that command line the way an analyst has to: /E mirrors every subfolder including empty ones, /Z enables restart-capable copying for large transfers, /MT:16 runs sixteen threads in parallel for speed, and /NFL /NDL suppress the file-and-directory listing Robocopy would otherwise print — a small detail that quietly reduces the amount of console output an attacker leaves behind for a human to notice. The destination folder name, SysHelper, is itself a small piece of tradecraft: it is deliberately chosen to look like a legitimate system utility to a human skimming a directory listing, not to defeat automated detection.\n\n### The Analyst's Question\n\nA lone process-creation event for Robocopy or xcopy proves nothing — both run constantly for entirely benign reasons across any real enterprise. The question that matters is correlation in TIME and PATH: does this copy operation follow, within minutes, a burst of share access from the SAME account and the SAME host, and does its destination sit outside the paths that host's legitimate software normally writes to?",
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "dsx-q1",
      "question": "An account reads 640 files from a network share it rarely touches, and four minutes later Robocopy consolidates a subset of those files into a folder under C:\\ProgramData on that same workstation. Which two ATT&CK techniques does this describe, in order, and which single tactic do BOTH of them belong to?",
      "options": [
        "T1039 (Data from Network Shared Drive) then T1074.001 (Local Data Staging) — both Collection",
        "T1074.001 (Local Data Staging) then T1039 (Data from Network Shared Drive) — both Exfiltration",
        "T1039 (Data from Network Shared Drive) then T1052.001 (Exfiltration Over USB) — both Exfiltration",
        "T1560.001 (Archive via Utility) then T1039 (Data from Network Shared Drive) — both Collection"
      ],
      "answer": 0,
      "explanation": "The share access comes first (T1039) and the local consolidation follows (T1074.001) — that is the correct order, and MITRE ATT&CK places BOTH techniques under the Collection tactic (TA0009), since nothing has left the host at either stage. Option b reverses the order and wrongly assigns Exfiltration to techniques where data has not moved off the compromised system at all. Option c substitutes T1052.001 (USB exfiltration) for the staging step, which never happened in this scenario — no removable media is mentioned. Option d wrongly puts archiving (T1560.001, which needs staged files to already exist) BEFORE the share access that would have provided those files in the first place.",
      "xp": 20
    },
    {
      "type": "reading" as const,
      "id": "dsx-r3",
      "heading": "T1560.001 — Archive via Utility: Packaging for the Road",
      "content": "With the target files consolidated in one local folder, the next step in almost every real intrusion is T1560.001, Archive Collected Data: Archive via Utility — using a compression program, built-in or third-party, to package the staged files into a single file before they move any further. This is still, perhaps counter-intuitively, the COLLECTION tactic (TA0009), not Exfiltration: nothing has moved off the host yet. What has changed is that the data is now a single, transportable object rather than a folder full of individual files, and — when a password is applied — an object that content-inspection tools genuinely cannot look inside.\n\n### The Real Toolset\n\nMITRE ATT&CK documents an extensive, entirely mainstream toolset for this step. On Windows, RAR (most frequently cited across real intrusions), 7-Zip, and WinZip are the third-party archivers most commonly abused, alongside built-in Windows utilities like makecab and diantz (which produce Microsoft Cabinet .cab files) and even certutil — a certificate-management tool most administrators have never used for this purpose — repurposed purely for its ability to Base64-encode arbitrary data. Linux and macOS systems ship tar as their native archiving tool. ATT&CK's own procedure examples span more than eighty documented threat groups using this technique, including APT1, APT28, APT33, APT39, APT41, Lazarus Group, Kimsuky, Turla, FIN8, FIN13, HAFNIUM, and the ransomware operations Play, INC Ransom, and Wizard Crew — and the documentation is explicit that these groups CONSISTENTLY favour password-protected archives specifically for staged data ahead of exfiltration.\n\nA worked WinRAR command line, exactly as it would appear in EDR process-creation telemetry:\n\nRar.exe a -hpM3rid1an! -m5 -v1900m \"C:\\ProgramData\\SysHelper\\stage\\ClientMatters.rar\" \"C:\\ProgramData\\SysHelper\\stage\\*\"\n\nRead each flag: a means add to archive; -hp followed directly by the password with no space (M3rid1an! here) is the specific WinRAR switch that BOTH encrypts the archive's contents AND encrypts the file names and folder structure themselves — the plain -p switch by contrast only encrypts the data, leaving file names visible to anyone who opens the archive without a password; -m5 selects the maximum compression level; and -v1900m splits the output into 1900-megabyte volumes, a size chosen because it sits comfortably under many email attachment limits and some cloud-upload chunking thresholds (a manual, low-tech cousin of the automated T1030 size-limit evasion covered later in this room).\n\n### Why the Password Matters to a Defender\n\nA password-protected archive is not a neutral technical detail — it is precisely what defeats content-inspection Data Loss Prevention. Pattern-matching and document-fingerprinting engines, the mechanisms the 'DLP for SOC Analysts' room covers in depth, work by reading the CONTENTS of a file. An archive encrypted with -hp gives that engine nothing to read at all; at best, a mature DLP or EDR platform can flag the metadata fact that an unusually large, freshly created, password-protected archive exists in a non-standard location — a much weaker, noisier signal than direct content matching, but often the only signal left once the archive step is complete.\n\n### The Analyst's Question\n\nSeeing rar.exe, 7z.exe, or tar run is meaningless by itself — every one of them runs constantly for legitimate reasons. The two details worth checking are LOCATION (is the archive utility running from its normal installed path, e.g. C:\\Program Files\\WinRAR, against a normal working folder — or from an unusual folder, on files that were JUST staged there) and the -hp/-p FLAG itself (a password-protected archive appearing in a staging folder that has no earlier history of ever containing one is a materially stronger signal than an unprotected .zip a user made to send a colleague a handful of files).",
      "checkpoint": {
        "question": "In WinRAR's command-line syntax, what does the -hp switch do that the plain -p switch does NOT?",
        "options": [
          "-hp only works on Linux and macOS, while -p is the Windows-only equivalent switch",
          "-hp encrypts the archive's data AND its file names/folder structure; -p encrypts only the data, leaving file names visible without the password",
          "-hp permanently deletes the original unarchived files after compression, while -p always leaves them in place",
          "-hp is only valid when splitting an archive into multiple volumes with -v, and has no effect otherwise"
        ],
        "answer": 1,
        "explanation": "The distinguishing feature of -hp is that it encrypts BOTH the archive's contents and its file/folder names and structure, so nothing about what is inside — not even the file names — is visible without the password. Plain -p only encrypts the data itself, leaving the file listing readable by anyone who opens the archive. Both switches work identically on Windows, Linux, and macOS builds of RAR. Neither switch has anything to do with deleting source files, and -hp works independently of whether the archive is split into volumes with -v."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "dsx-q2",
      "question": "A colleague argues: 'The moment the attacker password-protects and compresses the staged files with WinRAR, that IS the exfiltration step — that's clearly the theft.' What is wrong with this claim, and what tactic does T1560.001 (Archive via Utility) actually belong to per MITRE ATT&CK?",
      "options": [
        "The colleague is wrong — T1560.001 belongs to the Collection tactic, since the files have only been packaged, not moved off the host; the tactic only becomes Exfiltration at the technique that actually removes the data from the compromised system",
        "The colleague is correct — any password-protected archive automatically counts as Exfiltration under ATT&CK, since a password is the specific boundary the framework uses to separate the two tactics",
        "The colleague is correct, but only for 7-Zip archives specifically — WinRAR archives are classified Collection while 7-Zip archives are always classified Exfiltration",
        "The tactic cannot be determined without first knowing the archive's file extension, since ATT&CK assigns tactics purely from file extensions"
      ],
      "answer": 0,
      "explanation": "T1560.001 sits under the Collection tactic (TA0009) precisely because packaging data does not move it anywhere — the archive still sits on the same host it was created on. The tactic changes to Exfiltration only at the technique that actually removes data from the compromised system (T1052.001, T1567.002, T1048, etc.). ATT&CK does not use password-protection as a tactic boundary at all (option b), does not classify archive tools differently by vendor/format (option c — WinRAR and 7-Zip are both named under the same T1560.001 technique), and tactic assignment has nothing to do with file extensions (option d).",
      "xp": 20
    },
    {
      "type": "reading" as const,
      "id": "dsx-r4",
      "heading": "The Concrete Signs: What Points to Staging-and-Archiving Abuse",
      "content": "By the end of the archiving step, an attacker has produced exactly one artefact worth hunting for: a single, often password-protected, often unusually large file that did not exist an hour ago, sitting in a folder that does not normally contain one. Four concrete signals, read together rather than individually, separate this from routine, harmless compression activity.\n\n### 1. The Archive Is New, and the Folder Is Wrong\n\nA freshly created .rar, .7z, or .zip file is unremarkable in a Downloads folder or a user's own Documents. The same file appearing for the first time in C:\\ProgramData, C:\\Windows\\Temp, or any path a human did not choose by hand through a Save-As dialog is a materially different signal — those paths exist for applications to use, not for people to manually park files in.\n\n### 2. The Size and the Source Line Up\n\nAn archive whose size roughly matches the volume of data just read from a network share in reading r1 of this room is telling its own story: this file IS the packaged version of that earlier bulk access. A SOC that can correlate 'this account read roughly 400MB from the ClientMatters share nine minutes ago' against 'this account's workstation just produced a 380MB password-protected archive' has moved from two separate weak signals to one strong, coherent one.\n\n### 3. The Tool Ran From an Unexpected Path or Parent Process\n\nWinRAR launched by explorer.exe from its normal installed location, against a folder the user opened by hand, is ordinary desktop use. The identical binary launched by cmd.exe or powershell.exe, with no interactive Explorer window ever opened, against a folder the user has never navigated to in their file-access history, is a process-tree pattern worth escalating — the same 'right tool, wrong context' principle this curriculum's other rooms apply to living-off-the-land binaries generally.\n\n### 4. It Is Password-Protected, and It Wasn't Before\n\nAs the previous reading established, a password-protected archive defeats content inspection outright. A host or department that has never produced a single -hp-flagged archive in its EDR history suddenly producing one is a stronger signal than the mere presence of an archive utility running, precisely because legitimate day-to-day compression (zipping a folder to email a colleague) essentially never bothers with a password.\n\n### Putting the Four Together\n\nNone of these four signals alone justifies escalation — plenty of legitimate software creates large archives in ProgramData, plenty of IT scripts run compression tools from cmd.exe, and some genuinely cautious employees do password-protect the odd file. What changes the picture is TWO OR MORE of these four converging on the same host, the same account, and the same short time window as the share-access burst from reading r1 and the staging copy from reading r2. A single archive-creation event is a data point. An archive that is new, in the wrong folder, sized like the share access that preceded it, launched from an unexpected process, and password-protected for the first time on that host, is a case.",
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "dsx-r5",
      "heading": "T1052.001 — Exfiltration Over USB: The Physical Channel",
      "content": "With the packaged archive ready, T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB — is MITRE ATT&CK's name for the most direct way it can leave a host: copied straight onto removable media. This is the first technique in this room's chain that belongs to the EXFILTRATION tactic (TA0010) rather than Collection, because this is the step where data actually moves outside the compromised system's own storage.\n\nATT&CK's documentation is direct about why this channel remains relevant even in a heavily networked world: it is 'particularly effective in air-gapped environments' — networks deliberately kept disconnected from the internet specifically to prevent exactly the kind of network-based exfiltration this room otherwise focuses on — where 'the USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.' Several real, documented malware families exist specifically for this channel: Agent.btz creates files on inserted USB drives containing information about the infected system; Machete copies files into hidden folders on removable drives; Remsec contains a module purpose-built to move data out of air-gapped networks via USB; USBStealer exfiltrates collected files through removable media; and SPACESHIP is specifically designed to copy previously staged data the moment a USB drive is inserted, automating the exact hand-off this room's chain describes. Among named threat groups, Mustang Panda has used customised PlugX variants for USB-based exfiltration, and Tropic Trooper has employed USB storage devices as an exfiltration channel in its own documented campaigns.\n\n### What This Looks Like in Telemetry\n\nUnlike a network transfer, USB exfiltration leaves no packet capture at all — every scrap of evidence lives in endpoint telemetry. The sequence an analyst looks for is: a USB Mass Storage device-insertion event, immediately followed by a large file-write operation from a local or staged folder to the newly mounted drive letter. A representative correlation query against Microsoft Defender for Endpoint's Advanced Hunting telemetry illustrates the shape (this is a teaching illustration of the QUERY STRUCTURE, not a literal copy-pasteable production rule):\n\nDeviceEvents\n| where ActionType == \"UsbDriveMounted\"\n| join kind=inner (\n    DeviceFileEvents\n    | where ActionType == \"FileCreated\"\n    | where FolderPath startswith \"D:\\\\\" or FolderPath startswith \"E:\\\\\"\n) on DeviceId\n| where Timestamp1 between (Timestamp .. Timestamp + 5m)\n| project DeviceName, AccountName, FolderPath, FileName, Timestamp\n\nRead the logic in plain language: find every USB mount event, then find file-creation events on a removable drive letter within five minutes of that mount, on the same device — the exact pairing a real investigation performs by hand when it does not have this correlation pre-built.\n\n### Why This Technique Matters to This Curriculum Specifically\n\nUSB-based exfiltration already appears repeatedly across this platform's live SOC feed and scenario library — it is one of the most frequently PRACTISED techniques a student encounters while investigating live incidents. What has been missing until this room is the THEORY behind it: the technique ID, the tactic, the real documented tooling, and the detection logic. If you have already investigated a USB-exfiltration case on the dashboard, this reading is the missing explanation for what you were looking at.",
      "checkpoint": {
        "question": "Per ATT&CK's own documentation, why does Exfiltration Over USB (T1052.001) remain relevant even in heavily networked environments?",
        "options": [
          "It is the only exfiltration technique MITRE ATT&CK formally recognises, so every other channel in this room is technically a sub-technique of it",
          "It is particularly effective in air-gapped environments — networks deliberately disconnected from the internet — where the USB device can be the final exfiltration point or a way to hop between otherwise disconnected systems",
          "USB drives are undetectable by any EDR platform currently on the market, unlike every network-based channel covered elsewhere in this room",
          "It requires no compromise of the target host at all, since USB drives can extract data through the drive's own firmware without any software involved"
        ],
        "answer": 1,
        "explanation": "ATT&CK's own documentation names air-gapped environments directly: a network deliberately kept offline has no path for T1567.002, T1048, or any other network-based channel this room covers, which is exactly why physical media stays relevant — as the final exfiltration point, or as a way to bridge between two otherwise disconnected systems. It is one of many named exfiltration techniques, not the sole one others derive from. USB activity is absolutely detectable through endpoint telemetry (the DeviceEvents/DeviceFileEvents correlation this reading shows is exactly that). And every documented case in this reading requires the host itself to be compromised first, in order to copy files onto the drive via normal software."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "dsx-r6",
      "heading": "The Channel Menu: Cloud Storage, Alternative Protocols, and Size-Limit Evasion",
      "content": "Physical media is only one of several channels an attacker can choose for the actual Exfiltration step, and the choice of channel usually comes down to what blends in best with the traffic a given network already produces.\n\n### T1567.002 — Exfiltration to Cloud Storage\n\nATT&CK's Exfiltration Over Web Service: Exfiltration to Cloud Storage describes uploading the packaged data to a cloud storage service instead of relying on the attacker's own command-and-control infrastructure — a choice that provides real operational cover, since legitimate traffic to major cloud storage providers already flows out of almost every corporate network. The documented real-world usage is extensive: APT41 has used OneDrive for exfiltration; Lazarus Group built custom tooling (dbxcli) specifically targeting Dropbox; Scattered Spider has exfiltrated to MEGA, Snowflake, and AWS S3; Storm-0501 used the general-purpose cloud-transfer utility Rclone alongside MegaSync; and Turla has uploaded stolen files to both OneDrive and the file-sharing service 4shared. Rclone in particular deserves attention as a tool: it is a legitimate, open-source command-line utility built to sync files with dozens of cloud providers — Dropbox, Google Drive, Amazon S3, and MEGA among them — and its total legitimacy as IT tooling is exactly what makes its presence on an unexpected host such a strong signal when found.\n\n### T1048 — Exfiltration Over Alternative Protocol\n\nThis technique covers using a DIFFERENT protocol than whatever the attacker's main command-and-control channel already uses — FTP, SMTP (email), HTTP/S, DNS, or SMB, moved over using standard, unremarkable OS utilities like curl or the built-in Windows networking stack. ATT&CK splits it into three sub-techniques by how the alternate channel is protected: T1048.001 (Exfiltration Over Symmetric Encrypted Non-C2 Protocol), T1048.002 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol), and T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol). DNS tunnelling — encoding data into DNS query subdomains so it travels disguised as ordinary name-resolution lookups — is the technique's most distinctive and hardest-to-catch form specifically because most networks inspect DNS traffic far less closely than HTTP/S, and because nobody generates this traffic pattern by accident: seeing it is close to a guarantee of deliberate intent.\n\n### T1030 — Data Transfer Size Limits\n\nMany detection systems are tuned to flag transfers ABOVE a size threshold — precisely the kind of volume-based rule this room's earlier readings have described. T1030 is ATT&CK's name for the direct countermeasure: exfiltrating in small, fixed-size chunks specifically to stay under that threshold. The documentation is concrete about how far real actors take this: APT28 has split archived exfiltration files into chunks smaller than 1MB each; LuminousMoth split archived files into multiple parts specifically to bypass a 5MB limit its target environment enforced; APT41 divides post-exploitation payloads into fixed-size chunks for the same evasive purpose; Carbanak exfiltrates data in compressed chunks just over 4096 bytes; and Helminth, at the most extreme end, splits its exfiltrated data into 23-byte segments sent one at a time via DNS queries. Rclone — the same legitimate sync tool named above — even ships a built-in 'chunker' feature for exactly this purpose, and Cobalt Strike, a widely used (and widely abused) penetration-testing platform, automatically breaks large datasets into smaller chunks as a built-in behaviour.\n\n### The Channel Menu, Side by Side\n\n| Channel | Technique | Real example |\n| --- | --- | --- |\n| Physical medium (USB) | T1052.001 | SPACESHIP auto-copies staged data on USB insertion |\n| Cloud storage | T1567.002 | Scattered Spider to MEGA/Snowflake/S3; Storm-0501 via Rclone |\n| Alternative protocol (incl. DNS tunnelling) | T1048 (.001/.002/.003) | Helminth: 23-byte segments over DNS queries |\n| Chunking below a size threshold | T1030 | LuminousMoth: split files to bypass a 5MB limit |\n\nEvery one of these is the same underlying decision, made differently: how do I move this archive off the host in a way that looks, to whatever is watching, like something other than an attack?",
      "checkpoint": {
        "question": "Per this reading, why is Rclone specifically worth an analyst's attention when it appears on a host that has no legitimate reason to run it?",
        "options": [
          "Rclone is malware with no legitimate use case at all, so its mere presence on any host is definitive, standalone proof of compromise with no further context needed",
          "Rclone is a genuinely legitimate, widely used open-source cloud-sync tool with a built-in chunking feature — its very legitimacy is what makes it a strong signal in the wrong context",
          "Rclone only works over DNS tunnelling, so its presence always indicates T1048 specifically and can never indicate the cloud-storage channel T1567.002 covered earlier",
          "Rclone requires domain administrator privileges to install, so its presence always indicates a privilege-escalation event occurred somewhere earlier in the intrusion"
        ],
        "answer": 1,
        "explanation": "The reading is explicit that Rclone is a genuinely legitimate, widely used open-source cloud-sync utility (used by real IT teams for entirely ordinary purposes) that real threat actors (Storm-0501 among others) have also abused specifically because that legitimacy provides cover — and it even ships a built-in chunking feature relevant to T1030. Its presence is not proof of malware by itself; it is a strong signal specifically in the WRONG CONTEXT (a host/account with no business reason to run it). It supports many cloud providers and plain file operations, not only DNS tunnelling, so it is not tied exclusively to T1048. Installing and running Rclone as a regular user application requires no domain administrator privileges at all."
      },
      "xp": 5
    },
    {
      "type": "matching" as const,
      "id": "dsx-m1",
      "heading": "Match Each Technique to Its Real ATT&CK Tactic",
      "instructions": "Match each technique from this room to the ATT&CK tactic it actually belongs to per MITRE's own classification — not the tactic that feels intuitive.",
      "pairs": [
        {
          "id": "p1",
          "left": "T1039 — Data from Network Shared Drive",
          "right": "Collection"
        },
        {
          "id": "p2",
          "left": "T1074.001 — Data Staged: Local Data Staging",
          "right": "Collection"
        },
        {
          "id": "p3",
          "left": "T1560.001 — Archive Collected Data: Archive via Utility",
          "right": "Collection"
        },
        {
          "id": "p4",
          "left": "T1052.001 — Exfiltration Over Physical Medium: USB",
          "right": "Exfiltration"
        },
        {
          "id": "p5",
          "left": "T1567.002 — Exfiltration Over Web Service: Cloud Storage",
          "right": "Exfiltration"
        },
        {
          "id": "p6",
          "left": "T1030 — Data Transfer Size Limits",
          "right": "Exfiltration"
        }
      ],
      "explanation": "The pattern this room has taught end to end: reaching for data (T1039), consolidating it locally (T1074.001), and packaging it (T1560.001) are ALL still the Collection tactic (TA0009) — nothing has moved off the host at any of those three stages. Only once a technique actually removes data from the compromised system does the tactic become Exfiltration (TA0010) — whether that removal is over a physical USB drive (T1052.001), to a cloud storage service (T1567.002), or by evading volume-based detection thresholds with size-limited chunks (T1030). Confusing archiving for exfiltration is one of the most common tactic-mapping mistakes a new analyst makes, precisely because compressing and password-protecting data FEELS like the theft — this room exists specifically to correct that instinct.",
      "xp": 25
    },
    {
      "type": "log_analysis" as const,
      "id": "dsx-la1",
      "heading": "Investigate: A Large Outbound Transfer to mega.nz",
      "context": "Meridian Law Group's paralegal m.alvarez has legitimate VPN access, but this session originates from an unusual off-hours window. Earlier in the shift, m.alvarez's account generated an unusually large burst of file-share access on \\\\FS-LAW01\\ClientMatters$, and a new password-protected archive appeared shortly afterward in C:\\ProgramData\\SysHelper\\stage on WKS-LAW-214. The firewall record below captures what happened next.",
      "event": megaUploadEvent,
      "questions": [
        {
          "question": "Which pair of fields together gives the clearest evidence that this session is a bulk upload rather than ordinary encrypted web browsing?",
          "options": [
            "data.action (\"accept\") and data.proto (6) — since any accepted TCP session is inherently a bulk-upload indicator regardless of any other field",
            "data.sentbyte (796,305,664) and data.rcvdbyte (88,240) — an extremely upload-heavy ratio, the inverse of ordinary browsing where far more is downloaded than sent",
            "data.srcport (51882) and data.dstport (443) — since any connection using an ephemeral source port above 50000 is inherently suspicious",
            "data.vd (\"root\") and data.policyid (14) — since these fields identify which firewall policy processed the session"
          ],
          "answer": 1,
          "explanation": "The sentbyte/rcvdbyte pair shows roughly 760MB sent against only about 86KB received — a massively upload-heavy, inverted ratio. Ordinary web browsing is overwhelmingly download-heavy (loading pages, images, video), so a session that sends far more than it receives is exactly the anomaly this curriculum's exfiltration-detection material elsewhere teaches you to look for. data.action and data.proto simply describe that the session was permitted over TCP, which is true of the vast majority of ordinary traffic too. An ephemeral source port in the 50000s is completely normal for any outbound client connection. data.vd and data.policyid are administrative/routing fields with no bearing on whether the session itself is a bulk transfer.",
          "xp": 20
        },
        {
          "question": "Given this room's investigation workflow, what should the analyst check NEXT before reaching a verdict on this session?",
          "options": [
            "Whether mega.nz's TLS certificate is currently valid, since an expired certificate would be the only fact capable of establishing this session as malicious",
            "Whether the same account and host produced a matching share-access burst and a freshly created password-protected archive in the time window immediately before this upload",
            "Whether the destination IP is located outside the paralegal's own home country, since foreign-hosted IP addresses are inherently proof of an attack",
            "Whether the session used port 443 rather than port 80, since any traffic on port 443 is automatically suspicious regardless of content"
          ],
          "answer": 1,
          "explanation": "This room's whole investigation workflow (reading r8) is built on correlating the chain: check whether the SAME account/host also shows the earlier stages — a share-access burst (T1039) and a freshly created, password-protected archive (T1560.001) — in the window before this transfer. That correlation is what turns one firewall record into a confirmed case. A certificate-validity check says nothing about authorization to upload data (a perfectly valid TLS certificate secures plenty of malicious sessions too). Geographic destination alone, with no other context, is exactly the weak, single-signal reasoning this room warns against. Port 443 is the standard, overwhelmingly common port for ALL encrypted web traffic, legitimate and malicious alike — it carries no signal on its own.",
          "xp": 20
        }
      ]
    },
    {
      "type": "question" as const,
      "id": "dsx-q3",
      "question": "A workstation with a strict USB-blocking policy shows a sudden burst of unique DNS queries to subdomains that look like encoded data, immediately after a large password-protected archive was created on that host — with no unusual HTTPS or cloud-storage traffic accompanying it. Which technique best fits this pattern, and why might an attacker prefer it over the cloud-storage channel covered earlier in this room?",
      "options": [
        "T1048 (Exfiltration Over Alternative Protocol) via DNS tunnelling — chosen because DNS resolution traffic typically receives far less inspection than HTTP/S uploads, letting small amounts of data slip past detections tuned for large file transfers",
        "T1567.002 (Exfiltration to Cloud Storage) — DNS lookups are simply the first step of any cloud upload, so this is functionally the same technique as an HTTPS upload to a service like MEGA",
        "T1052.001 (Exfiltration Over USB) — a burst of DNS queries always confirms a USB device was just inserted, since Windows logs USB insertion events exclusively through DNS",
        "T1074.001 (Local Data Staging) — a burst of DNS queries is itself a staging action, meaning the data has not actually left the host at any point in this scenario"
      ],
      "answer": 0,
      "explanation": "DNS tunnelling under T1048 is exactly this pattern: data encoded into DNS query subdomains, chosen specifically because most network monitoring inspects DNS far less closely than HTTP/S traffic, and because a USB-blocking policy has already closed off the T1052.001 channel this attacker might otherwise have preferred. Option b confuses two unrelated things — a normal cloud-storage upload does not primarily manifest as a burst of unique encoded DNS subdomains; that pattern IS the DNS-tunnelling technique itself. Option c invents a mechanism that does not exist: USB device insertion is logged by the OS/EDR directly, never 'through DNS.' Option d misapplies staging, which by definition keeps data on the host — this scenario describes queries actively leaving the host over the network.",
      "xp": 25
    },
    {
      "type": "analyst_choice" as const,
      "id": "dsx-ac1",
      "heading": "Triage: A Large Nightly Transfer From BKP-VEEAM-01",
      "scenario": "A separate alert fires the same week for another large outbound HTTPS session — this time from the backup server BKP-VEEAM-01, at 02:00, carrying roughly 11.6GB. The underlying detection rule matches any session exceeding 500MB sent, with no allowance for account type, destination, or historical baseline.",
      "event": veeamBackupEvent,
      "correct_verdict": "false_positive",
      "explanation": "Every discriminator this room's reading r8 names checks out as legitimate: a dedicated service account (svc-veeam-backup, never a human's own login), a documented change ticket (CHG-2026-1187), six months of an identical recurring schedule at 02:00, and a sanctioned first-party destination — the organisation's OWN Azure Blob Storage container, not an unrelated personal or consumer service. The it_verify_message confirms every one of these facts directly from IT. This is the legitimate-backup shape this room warned about: it looks structurally identical to the attack chain, and the four context checks — not the volume — are what separate it.",
      "fp_trap": "The raw byte count here (roughly 11.6GB) is actually LARGER than the malicious mega.nz upload in this room's log_analysis task — if volume alone decided the verdict, this would look like the more serious case. Escalating purely on transfer size, without checking the account type, the destination, and the historical baseline this room's investigation workflow calls for, is exactly the false-positive flood that trains a SOC to stop trusting its own large-transfer alerts.",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "dsx-r7",
      "heading": "Putting the Chain Together: The mega.nz Case",
      "content": "An investigation built on one raw log line rarely resolves anything on its own — that is the entire reason the previous six readings walked through a chain rather than a single technique. This room's core practice section puts that chain to work: a large, allowed outbound transfer to a personal cloud service, seen through a firewall's own traffic log, on a host and account already flagged by the earlier stages of this exact chain.\n\nWork through the log_analysis task now, applying everything the last six readings established: check the destination against what this organisation's account and role would legitimately need, check the byte counts for the same inverted, upload-heavy ratio this curriculum's exfiltration-detection material elsewhere teaches you to look for, and check the timing against a normal working pattern.",
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "dsx-r8",
      "heading": "The Legitimate-Backup Trap, and the Full Investigation Workflow",
      "content": "Every signal this room has covered so far — a burst of share access, a new archive, a large outbound transfer — has one structural problem: legitimate enterprise backup software produces an almost identical shape, every single night, forever. A backup job also reads a large volume of data from a share (often the ENTIRE share, not a subset), also consolidates it, frequently also compresses it, and also transfers a large volume off the host to a remote destination. If volume and shape alone decided the verdict, every mature organisation's own backup infrastructure would be a permanent false-positive machine.\n\n### The Shape Is Identical. The Context Is Not.\n\nFour concrete differences separate a scheduled backup job from the attack chain this room has walked, and none of them is the size of the transfer:\n\n**The account.** A backup job runs under a dedicated SERVICE account (a naming convention like svc-backup or svc-veeam-agent recurs constantly across real environments) with no interactive logon history, never under a human's own everyday account.\n\n**The documentation.** A legitimate change to a backup schedule, or the backup job's ordinary recurring existence, is tied to a documented change ticket or a standing, approved configuration IT can point to on request — not improvised activity with no paper trail anywhere.\n\n**The consistency.** A real backup job runs at the SAME time, to the SAME destination, at roughly the SAME volume, night after night for months — a baseline any UEBA or simple historical query can confirm in seconds. An attacker's version of this chain, by contrast, is a one-off: it has never happened on this host before, and — critically — it usually will not happen again from the same host once the data is taken.\n\n**The destination.** A legitimate backup job's destination is the organisation's OWN sanctioned infrastructure — a dedicated backup vendor's cloud repository, or the organisation's own cloud storage account — never an unrelated personal or consumer service the backup vendor has no relationship with.\n\n### A Worked Correlation Query\n\nPutting the whole chain together into one detection is a matter of joining the stages this room has covered by host, account, and a tight time window — illustrated here in pseudocode:\n\nlet shareAccess = SecurityEvent | where EventID == 5145 | summarize FileCount = count() by Account, IpAddress, bin(TimeGenerated, 15m);\nlet archiveCreate = DeviceProcessEvents | where FileName in (\"rar.exe\",\"7z.exe\",\"winrar.exe\") and ProcessCommandLine has \"-hp\";\nlet largeEgress = CommonSecurityLog | where DeviceVendor == \"Fortinet\" and SentBytes > 500000000;\nshareAccess | join kind=inner archiveCreate on Account | join kind=inner largeEgress on Account\n| where FileCount > 200\n\nRead the logic: find accounts reading over 200 files from a share in a 15-minute window, THEN check whether that same account also ran a password-protected archive utility, THEN check whether that same account ALSO produced a large outbound transfer — three separate, individually weak signals from three different log sources, joined into one strong case.\n\n### The Investigation Workflow, Step by Step\n\n1. **Identify the trigger.** Which stage of the chain fired first — an unusual share-access volume, a new password-protected archive, or a large outbound transfer?\n2. **Walk backward through the chain.** If the trigger was the egress, check for a matching archive-creation event and a matching share-access burst on the same host in the preceding window. If the trigger was the archive, check for the share access that likely fed it.\n3. **Check the account type.** Interactive human account, or a documented service account?\n4. **Check for a change ticket or standing documentation.** Does IT have a record explaining this activity?\n5. **Check the historical baseline.** Has this exact pattern — this account, this destination, this rough volume — happened before, repeatedly, on a consistent schedule?\n6. **Check the destination.** Sanctioned corporate/vendor infrastructure, or an unrelated personal/consumer service?\n7. **Reach a verdict.** All four context checks pointing to 'legitimate' closes the case as expected activity. Any one of them missing — no ticket, no history, an unfamiliar destination, or an interactive account — escalates to containment: isolate the host, preserve the archive and the share-access logs as evidence, and treat the finding as a confirmed data-theft chain rather than routine IT work.",
      "checkpoint": {
        "question": "Per this reading, which of the four discriminators is described as the one a simple historical query or UEBA baseline can confirm 'in seconds'?",
        "options": [
          "The account type — because service accounts are always named starting with the exact prefix svc- in every organisation without exception",
          "The consistency of the pattern — whether this same time, destination, and rough volume has recurred night after night for months",
          "The destination — because any destination whose domain name contains the word backup is automatically legitimate",
          "The size of the transfer — because any transfer under a fixed size threshold can never be an attack"
        ],
        "answer": 1,
        "explanation": "The reading specifically calls out CONSISTENCY — the same time, destination, and rough volume recurring night after night for months — as the discriminator a historical query or UEBA baseline can confirm quickly, precisely because it is a pattern-over-time check rather than a judgment call. The svc- naming convention is described as something that 'recurs constantly,' not as a universal, exception-free rule. A domain merely containing the word 'backup' proves nothing about legitimacy on its own (an attacker can name infrastructure anything). And this room has been explicit throughout that volume/size alone, with no fixed threshold, never decides a verdict."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "dsx-q4",
      "question": "BKP-VEEAM-01 reads the entire Client Matters share every night at 02:00, compresses it, and uploads roughly 12GB to the organisation's own Azure Blob Storage backup container under a documented, approved change ticket, at a volume and time that has been identical for the past six months. Per this room's investigation workflow, which factor is the WEAKEST reason to rule this out as an attack, and which is the STRONGEST?",
      "options": [
        "Weakest: that the job reads and compresses the entire share (an attacker's staging-and-archiving stage can look identical); Strongest: the combination of a dedicated service account, a documented change ticket, six months of consistent scheduling, and a sanctioned first-party destination",
        "Weakest: the destination being Azure Blob Storage, since Microsoft-owned cloud infrastructure can never, under any circumstances, be used as an exfiltration destination by an attacker",
        "Weakest: the 12GB volume, since this room establishes a universal rule that any transfer under a fixed size threshold can never be classified as exfiltration",
        "Strongest: that the transfer happens at 02:00, since this room establishes that any nighttime transfer is, by definition, always a legitimate scheduled job"
      ],
      "answer": 0,
      "explanation": "Reading big-share-access, staging, and archiving is exactly the SHAPE an attacker's chain also produces (this room says so explicitly), so that shape alone is the weakest discriminator. What actually rules this out is the CONTEXT this room's investigation workflow names directly: a dedicated service account, a documented ticket, months of consistent recurring scheduling, and a sanctioned first-party destination — together, not any one alone. Option b is false; Scattered Spider, among others documented in this room, has exfiltrated to major legitimate cloud providers precisely because that infrastructure is trusted. Option c invents a size rule this room never states — no fixed byte threshold decides a verdict anywhere in this material. Option d is equally invented; this room's readings state plainly that timing is only one of several factors, and an attacker's exfiltration is frequently timed for off-hours specifically to blend in, not ruled out by it.",
      "xp": 25
    },
    {
      "type": "ordering" as const,
      "id": "dsx-o1",
      "heading": "Order the Chain: Collection to Exfiltration",
      "instructions": "Place these four stages of this room's ATT&CK chain in the order a real intrusion actually performs them, from first reaching the data to finally moving it off the host.",
      "items": [
        {
          "id": "step-share",
          "text": "Read files from the network share the compromised account can legitimately reach (T1039, Collection)"
        },
        {
          "id": "step-stage",
          "text": "Consolidate the interesting files into one local folder on the compromised host (T1074.001, Collection)"
        },
        {
          "id": "step-archive",
          "text": "Compress and typically password-protect the staged files with an archive utility (T1560.001, Collection)"
        },
        {
          "id": "step-channel",
          "text": "Move the packaged archive off the host — over USB, to cloud storage, or via an alternative protocol (T1052.001 / T1567.002 / T1048, Exfiltration)"
        }
      ],
      "correct_order": [
        "step-share",
        "step-stage",
        "step-archive",
        "step-channel"
      ],
      "explanation": "This is the exact chain this room has walked reading by reading: an attacker must first reach the data (T1039) before they can consolidate it (T1074.001), must consolidate it before there is anything to package (T1560.001), and must package it before there is a single, transportable object to actually move off the host (the Exfiltration-tactic techniques). Each stage depends on the one before it — you cannot archive files that were never staged, and you cannot stage files that were never read from a share in the first place. This is also precisely the order this room's own detection workflow (reading r8) correlates backward through once an alert fires on any single stage.",
      "xp": 25
    },
    {
      "type": "flag" as const,
      "id": "dsx-f1",
      "prompt": "This room's reading on Archive via Utility (T1560.001) covers the specific WinRAR command-line switch that encrypts BOTH an archive's contents AND its file names/folder structure in one step — distinct from the plain -p switch, which encrypts only the data. What is that exact switch? Answer with the flag exactly as it appears in the reading (e.g. a two-character switch beginning with a hyphen).",
      "answer": "-hp",
      "hint": "Covered in the reading 'T1560.001 — Archive via Utility: Packaging for the Road' — distinct from the plain -p switch, which does not also hide file names.",
      "xp": 15
    }
  ]
};

export const roomsBatch45 = [dataStagingExfilRoom];
