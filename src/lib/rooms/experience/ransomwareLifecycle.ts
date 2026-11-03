import type { RoomExperience } from "./types";

// Experience for "ransomware-full-lifecycle" (rooms-batch-33.ts).
//
// The 3D world is a ring of armoured GATES around a holographic globe: each
// station is a gate in the access sequence, and the globe lights up one more
// region as the affiliate's intrusion is driven back, gate by gate.
//
// Every briefing lab teaches a reading hands-on. To guarantee a lab never
// leaks a graded answer, the labs run on a SEPARATE, fictional case:
//   "Meridian Freight", hosts WKS-FIN-0912 / SRV-LOG-07 / DC-MER-01,
//   affiliate account m.pratt, extension ".locked77", archive tool MEGAcmd.
// None of these appears in any graded task (the room's case is NexaCorp,
// j.reyes, WKS-IT-0417 / SRV-FILES-04, rclone, extension .a8f2e91c,
// wuauclt32.exe), so working a lab can never hand over a graded value. Every
// lab agrees with the CURRENT text of the reading it sits under.
export const RANSOMWARE_LIFECYCLE: RoomExperience = {
  roomId: "ransomware-full-lifecycle",
  codename: "Operation Cold Vault",
  theme: "ransomware",
  scene: "gates",
  layout: "stage",
  handler: { name: "Dana Reyes", role: "SOC Lead, Night Shift" },
  briefing: [
    "02:47. A credential-dumping alert just fired on a helpdesk workstation.",
    "This is not the encryption. The encryption is days of work away, if we are slow.",
    "An affiliate is already inside, mapping the domain and stealing what matters before a single file locks.",
    "Every gate you clear is a stage we can still stop them at. Open them in order.",
  ],
  mission: "One affiliate, one intrusion, stage by stage: learn how ransomware really unfolds, then work the evidence from the first dump to the final gate before the vault closes.",
  estimate: "~115 min",
  look: { primary: "#22d3ee", secondary: "#a78bfa", warn: "#f59e0b" },
  stations: [
    {
      id: "intel",
      label: "Intel Gate",
      tagline: "How the industry works and how the affiliate gets in",
      building: "archive",
      taskIds: ["rw-r1", "rw-r2", "rw-q1"],
    },
    {
      id: "breach",
      label: "Breach Gate",
      tagline: "Foothold, persistence, domain recon, and the first credential dump",
      building: "control",
      taskIds: ["rw-r3", "rw-r4", "rw-la1"],
    },
    {
      id: "spread",
      label: "Spread Gate",
      tagline: "Lateral movement across the fleet, then recovery and detection torn down",
      building: "office",
      taskIds: ["rw-r5", "rw-q2", "rw-m1", "rw-r6", "rw-o1"],
    },
    {
      id: "exfil",
      label: "Exfil Gate",
      tagline: "The highest-value window: bulk data leaving before anything is encrypted",
      building: "lab",
      taskIds: ["rw-r7", "rw-la2", "rw-ac1"],
    },
    {
      id: "final",
      label: "Final Gate",
      tagline: "Encryption fires fleet-wide. Scope the push, contain, and hand IR the facts",
      building: "vault",
      taskIds: ["rw-r8", "rw-la3", "rw-f1", "rw-qf1", "rw-q3", "rw-o2"],
      boss: true,
    },
  ],
  personas: {
    "rw-ac1": {
      name: "Priya Nair",
      role: "Change & Release Manager",
      line: "That archive server runs a records-migration job every night this quarter. I can pull the change ticket and the config if it helps.",
    },
  },
  briefings: {
    // ── Reading 1: RaaS economics & double extortion ────────────────────────
    "rw-r1": [
      {
        kind: "match",
        title: "Who is who in the economy",
        prompt: "The intrusion you will work is run by a small supply chain, not one gang. Match each role to what it actually does.",
        pairs: [
          { id: "op", left: "RaaS operator", right: "Builds and rents out the encryptor, leak site and negotiation portal", why: "The operator supplies the toolkit and takes a share of the ransom; it rarely runs the intrusion itself." },
          { id: "aff", left: "RaaS affiliate", right: "Buys or rents the toolkit and carries out the actual intrusion", why: "The affiliate does the phishing, credential theft and lateral movement, and keeps the larger share of any ransom." },
          { id: "iab", left: "Initial Access Broker", right: "Breaks in, then sells the ready-made foothold to whoever is buying", why: "An IAB specialises one layer upstream: it does nothing but gain access and sell it on." },
          { id: "brand", left: "A ransomware family name", right: "A brand for a rented toolkit, not one fixed group of people", why: "Two intrusions using the same encryptor can be run by different affiliates with different methods and tempo." },
        ],
      },
      {
        kind: "sort",
        title: "Does a clean restore defeat it?",
        prompt: "A victim restores every server from clean, immutable backups and refuses to pay. Sort each form of attacker leverage by whether that restore takes it away.",
        buckets: [
          { id: "gone", label: "Restore defeats it" },
          { id: "stays", label: "Survives the restore" },
        ],
        items: [
          { id: "enc", text: "Files locked by encryption, decryption key withheld", bucket: "gone", why: "A clean, tested backup makes this leverage collapse: the victim restores and ignores the note. This is exactly why operators needed something more." },
          { id: "steal", text: "A copy of sensitive data stolen before encryption, with a leak-site threat", bucket: "stays", why: "No restore un-steals data. This is the leverage double extortion adds, and why strong backups alone stopped being enough around 2019-2020." },
          { id: "avail", text: "Downtime while production is rebuilt", bucket: "gone", why: "Restoring from backup is what ends the downtime; recovery is the answer to this one." },
        ],
      },
      {
        kind: "sequence",
        title: "Where encryption sits",
        prompt: "Reading 1 says encryption is the last few minutes of a much longer intrusion. Tap the span in the order it actually runs, from first to last.",
        items: [
          { id: "a", text: "The affiliate gets in (days or weeks before anything locks)" },
          { id: "b", text: "They move through the network and steal the data that matters" },
          { id: "c", text: "Encryption finally runs: the last few minutes" },
        ],
        order: ["a", "b", "c"],
        doneNote: "If the SOC only defends 'the encryption', it is defending the last few minutes. Every earlier stage is a chance to stop the intrusion before the leverage leaves the building.",
      },
    ],

    // ── Reading 2: initial access vectors ───────────────────────────────────
    "rw-r2": [
      {
        kind: "match",
        title: "Vector to its fingerprint",
        prompt: "Three vectors account for most enterprise ransomware. Match each to the telemetry that gives it away.",
        pairs: [
          { id: "phish", left: "Phishing (T1566)", right: "An Office app spawns a script host, or a Downloads-folder exe runs minutes after an email", why: "The mail delivers a loader; the process tree shows the loader running. Ransomware phishing often aims at IT and helpdesk staff for their broader access." },
          { id: "edge", left: "Edge-device exploitation (T1190)", right: "An exploit-pattern request to a VPN or gateway portal, then a login with no phishing trace", why: "The appliance is internet-facing, usually runs no EDR, and is mass-exploited within days of a CVE. The session afterwards looks like ordinary remote access." },
          { id: "rdp", left: "RDP brute force (T1110 then T1021.001)", right: "A burst of Event 4625 failures against an account, then a 4624 logon once one works", why: "With NLA on, the failures land as logon type 3, not type 10; the success is a type 10 RemoteInteractive logon." },
        ],
      },
      {
        kind: "sort",
        title: "Read the case, name the vector",
        prompt: "Each short case points at one of the three vectors. Sort them.",
        buckets: [
          { id: "p", label: "Phishing" },
          { id: "e", label: "Edge-device exploit" },
          { id: "r", label: "RDP brute force" },
        ],
        items: [
          { id: "c1", text: "A finance clerk opens an invoice; WINWORD.EXE spawns powershell.exe ninety seconds later.", bucket: "p", why: "An Office app spawning a script host right after an email is the phishing fingerprint." },
          { id: "c2", text: "The SSL-VPN portal logs an exploit-shaped request; the appliance is two versions behind a public CVE, and the account that logs in afterward has no phishing history.", bucket: "e", why: "Exploit pattern, unpatched internet-facing appliance, no phishing trace: edge-device exploitation." },
          { id: "c3", text: "Nine hundred Event 4625 failures hit one admin account overnight, all logon type 3, then one 4624 succeeds.", bucket: "r", why: "A failure burst then a success is credential guessing; type 3 is the NLA pre-auth failure, not a desktop session." },
          { id: "c4", text: "A newly disclosed CVE for the file-transfer gateway is mass-scanned worldwide; your appliance answers one of the probes and a session opens.", bucket: "e", why: "Internet-facing gateway, days after disclosure, session that looks authenticated from the inside: edge-device exploitation again." },
        ],
      },
      {
        kind: "inspect",
        title: "Why the vector changes the fix",
        prompt: "Open each remediation. The point of naming the vector is that the fixes are different; treating all three as 'the user should have known better' misses two of them.",
        artifact: "Remediation by vector",
        items: [
          { id: "pf", text: "Phishing case", tag: "User reporting, mail-gateway tuning", tone: "info", note: "Points toward the specific sender and domain, mail-gateway tuning, and user reporting. Only here does user awareness belong in the fix." },
          { id: "ef", text: "Edge-device case", tag: "Patch + invalidate sessions + reset", tone: "warn", note: "Points toward an urgent patch, a full session-token invalidation and a credential reset on that appliance. Patching alone does not undo credentials already stolen through the hole." },
          { id: "rf", text: "RDP case", tag: "Remove exposure + real MFA", tone: "warn", note: "Points toward removing the internet-facing RDP exposure entirely and enforcing real multi-factor authentication." },
        ],
      },
    ],

    // ── Reading 3: execution & persistence ──────────────────────────────────
    "rw-r3": [
      {
        kind: "sort",
        title: "Living off the land",
        prompt: "Sort these by whether a signed, built-in Windows tool is being reused to run a payload, which is exactly why file-reputation defences miss this stage.",
        buckets: [
          { id: "lol", label: "Signed Windows binary reused" },
          { id: "drop", label: "An obvious standalone dropped" },
        ],
        items: [
          { id: "mshta", text: "mshta.exe runs a remote script", bucket: "lol", why: "mshta.exe is a legitimate, signed Windows utility, favoured for running a loader without dropping an obviously-malicious exe." },
          { id: "regsvr", text: "regsvr32.exe loads a payload", bucket: "lol", why: "Another signed Windows LOLBin reused for execution." },
          { id: "certutil", text: "certutil.exe base64-decodes and downloads a second stage", bucket: "lol", why: "certutil is abused for its built-in decode and download, resembling a certificate operation." },
          { id: "evil", text: "evil_payload_final.exe runs from the Downloads folder", bucket: "drop", why: "A standalone, unsigned binary is exactly what file-reputation defences are good at catching, which is why affiliates prefer the LOLBins above." },
        ],
      },
      {
        kind: "inspect",
        title: "One task, or a fleet of them?",
        prompt: "Three scheduled-task events from Meridian Freight. Open each. Reading 3 says a single new task is usually routine IT; the same task appearing across many hosts at once is the emergency.",
        artifact: "Security Event 4698 'A scheduled task was created'",
        items: [
          { id: "one", text: "1 host: \\BackupVendor\\NightlyCatalog, created on SRV-LOG-07", tag: "Routine", tone: "trust", note: "A single new task on one server looks like IT automation and usually is. On its own it is a low-priority note." },
          { id: "many", text: "214 hosts: \\Microsoft\\Windows\\Update\\svcCheck, same name and action, all created within four minutes, all set to fire at 06:00", tag: "Domain-wide emergency", tone: "warn", note: "Same task name, same action, same run time across dozens or hundreds of hosts within minutes is the fleet-wide ransomware precursor. The dual purpose is the point: the mechanism that gives a day-one foothold is reused to fire the encryptor everywhere at once." },
          { id: "run", text: "1 host: a new HKCU Run key on WKS-FIN-0912", tag: "Single-host persistence", tone: "info", note: "Run and RunOnce keys are generally favoured for single-host persistence, not the timed, fleet-wide detonation a scheduled task enables." },
        ],
      },
      {
        kind: "match",
        title: "Persistence, the affiliate's way",
        prompt: "Match each mechanism to the role Reading 3 says it plays for a ransomware affiliate.",
        pairs: [
          { id: "sched", left: "Scheduled task (Event 4698)", right: "Day-one foothold, then reused to fire the encryptor fleet-wide at one time", why: "Its dual purpose, single-host survival and timed mass detonation, is why a rash of identical tasks is such a strong precursor." },
          { id: "runkey", left: "Registry Run / RunOnce key", right: "Generally single-host persistence rather than timed fleet-wide detonation", why: "The other common option, but it does not give the coordinated, scheduled push a task does." },
        ],
      },
    ],

    // ── Reading 4: discovery & credential access ────────────────────────────
    "rw-r4": [
      {
        kind: "match",
        title: "What each recon command reveals",
        prompt: "From one foothold, a few commands map the whole domain. Match each to what it tells the affiliate.",
        pairs: [
          { id: "da", left: "net group \"Domain Admins\" /domain", right: "Lists the most privileged accounts directly", why: "Enumerates the top-tier accounts the affiliate wants to reach." },
          { id: "trust", left: "nltest /domain_trusts", right: "Maps trusted domains that could widen the blast radius", why: "Trusts can extend the intrusion beyond the first domain." },
          { id: "whoami", left: "whoami /groups", right: "Checks the compromised account's own effective privileges", why: "Group nesting can quietly grant a helpdesk account far more than its title suggests." },
          { id: "sharp", left: "An automated collector (SharpHound-style)", right: "Pulls the whole picture in one pass, as a burst of high-volume LDAP queries", why: "Visible to a Domain Controller's own logs as an unusual LDAP burst: a real discovery-stage detection opportunity." },
        ],
      },
      {
        kind: "sort",
        title: "LSASS or DCSync?",
        prompt: "Both are credential access, but they reach different amounts. Sort each statement.",
        buckets: [
          { id: "lsass", label: "LSASS dump (T1003.001)" },
          { id: "dcsync", label: "DCSync (T1003.006)" },
        ],
        items: [
          { id: "l1", text: "Harvests whatever credential material is cached on one host", bucket: "lsass", why: "LSASS holds credentials of accounts that logged on to that host; you get that host's worth." },
          { id: "d1", text: "Asks a Domain Controller to replicate every account's password hash in one request", bucket: "dcsync", why: "An account with replication rights can impersonate a DC and pull the whole domain at once." },
          { id: "d2", text: "Needs an account holding Replicating Directory Changes rights", bucket: "dcsync", why: "That replication right is the prerequisite, and the DC's Event 4662 records the access." },
          { id: "l2", text: "Can request a narrow access mask like 0x1410 to stay quieter", bucket: "lsass", why: "Many dumpers use narrower masks than full access, so a rule keyed only on 0x1FFFFF misses them." },
        ],
      },
      {
        kind: "simulate",
        title: "Why one credential is the whole fleet",
        prompt: "Pick a credential the affiliate could steal and see whether it enables a coordinated, fleet-wide encryptor push. Try both.",
        checks: [
          { name: "Reach", question: "Can this credential reach every server and workstation at once?" },
          { name: "Push", question: "Does it enable one coordinated deployment (GPO, PsExec, RMM)?" },
        ],
        scenarios: [
          {
            id: "helpdesk",
            label: "One local workstation admin",
            detail: "Local admin on a single workstation, no domain-wide rights.",
            results: ["fail", "fail"],
            why: ["It reaches one host, not the fleet.", "Deploying host by host is a slow nuisance a SOC can usually catch and stop."],
            verdict: "Not enough. This is the slow path the affiliate wants to avoid.",
          },
          {
            id: "domainadmin",
            label: "A domain-wide administrative credential",
            detail: "A credential with administrative reach across the domain, as DCSync or a privileged dump can yield.",
            results: ["pass", "pass"],
            why: ["It can reach every reachable server and workstation.", "It enables the one coordinated push (Group Policy, PsExec or RMM) that turns an intrusion into a company-wide outage in minutes."],
            verdict: "This is exactly why the credential-access stage exists: the coordinated push needs domain-wide admin.",
          },
        ],
      },
    ],

    // ── Reading 5: lateral movement ─────────────────────────────────────────
    "rw-r5": [
      {
        kind: "match",
        title: "Tool to its telemetry",
        prompt: "Three legitimate admin tools do nearly all ransomware lateral movement. Match each to its giveaway.",
        pairs: [
          { id: "psexec", left: "PsExec (T1021.002, over SMB/admin shares)", right: "A type 3 network logon, then a new service install (7045 in System, 4697 in Security), often PSEXESVC", why: "PsExec copies itself to ADMIN$ and creates a service to run remotely; the logon-then-service pair is the signature." },
          { id: "wmi", left: "WMI (T1047)", right: "WmiPrvSE.exe as the unexpected parent of a process, with no new service", why: "A Win32_Process Create starts a remote process without a service and without touching ADMIN$, so it is quieter." },
          { id: "rdp", left: "RDP (T1021.001)", right: "Event 4624 logon type 10 (RemoteInteractive), sometimes with 4778/4779", why: "A full interactive graphical session; the noisiest of the three because a human is driving the keyboard." },
        ],
      },
      {
        kind: "sort",
        title: "Admin, or attacker?",
        prompt: "PsExec is legitimate and used constantly by IT. Sort what actually separates an attack from routine use.",
        buckets: [
          { id: "tell", label: "The real tell" },
          { id: "not", label: "Proves nothing on its own" },
        ],
        items: [
          { id: "pattern", text: "One account repeating type 3 logon then PSEXESVC across many hosts in minutes, from an unexpected source or hour", bucket: "tell", why: "Repetition across hosts in a short window, from an unexpected account/source/timing, is the signature; single-host IT admin essentially never looks like this." },
          { id: "present", text: "PsExec.exe is simply present on a server", bucket: "not", why: "IT uses PsExec constantly; its presence proves nothing." },
          { id: "svcname", text: "The service is named PSEXESVC", bucket: "not", why: "The default name proves nothing either way, and an attacker may rename it; the name alone cannot separate admin from attacker." },
          { id: "logon3", text: "The target-side logon is type 3", bucket: "not", why: "PsExec's target logon is type 3 whoever runs it; type 10 is the RDP logon on a different host." },
        ],
      },
      {
        kind: "inspect",
        title: "Trace it across the fleet",
        prompt: "A hunt at Meridian Freight returns these rows for one account. Open each. The job is reading the combination, not the single event.",
        artifact: "PsExec hunt · account MERIDIAN\\m.pratt",
        items: [
          { id: "r1", text: "SRV-LOG-07: 4624 type 3 from 10.12.0.44, then 7045 service PSEXESVC, 01:02", tag: "Host 1", tone: "warn", note: "The logon-then-service pair on the first server." },
          { id: "r2", text: "SRV-APP-21: same account, same source IP, 7045 PSEXESVC, 01:07", tag: "Host 2", tone: "warn", note: "The identical pattern repeats five minutes later on a second host." },
          { id: "r3", text: "SRV-DB-03: same account, same source IP, 7045 PSEXESVC, 01:13", tag: "Host 3", tone: "warn", note: "And again. One account, one source, the same pattern across three servers in minutes is lateral movement, not routine admin." },
          { id: "r4", text: "dcount(Computer) = 3, grouped by account", tag: "The scope line", tone: "info", note: "One finding tells you the pattern exists; the fleet hunt tells you how far it reaches. That is the move: scope every host the credential touched." },
        ],
      },
    ],

    // ── Reading 6: defense impairment ───────────────────────────────────────
    "rw-r6": [
      {
        kind: "match",
        title: "Technique to command and log",
        prompt: "Three techniques make recovery hard and leave the SOC little to work with. Match each to how it shows up.",
        pairs: [
          { id: "vss", left: "Inhibit System Recovery (T1490)", right: "vssadmin delete shadows /all /quiet, just before mass file activity", why: "Removes the Volume Shadow Copy snapshots that would otherwise restore pre-encryption files in minutes. ATT&CK files it under Impact, and affiliates leave it to the final minutes." },
          { id: "tool", left: "Disable or Modify Tools (T1685)", right: "EDR/AV stopped, Defender real-time protection off, or broad path exclusions added", why: "Done once the affiliate holds the privileges, usually before the noisy work, so it runs unseen. Tamper protection resists this on well-configured hosts." },
          { id: "log", left: "Clear Windows Event Logs (T1685.005)", right: "wevtutil cl Security, which itself writes a fresh Event 1102", why: "Clearing the log is logged: 1102 in Security, 104 in System, each naming who cleared it and when." },
        ],
      },
      {
        kind: "sort",
        title: "Loud, and almost unambiguous",
        prompt: "Each of these three techniques is loud in its own way and, outside its narrow legitimate context, close to unambiguous. Sort each observation by whether it is that near-certain signal or a benign look-alike.",
        buckets: [
          { id: "sig", label: "Near-certain malicious" },
          { id: "benign", label: "Its narrow legitimate context" },
        ],
        items: [
          { id: "s1", text: "vssadmin delete shadows /all /quiet launched from an Office child process on a workstation at 03:00", bucket: "sig", why: "There are very few legitimate reasons to wipe all shadow copies from an unexpected parent, outside a scheduled backup job." },
          { id: "b1", text: "A documented backup server running its normal retention job that rotates shadow copies on schedule", bucket: "benign", why: "This is the one narrow, scheduled context where the command is expected." },
          { id: "s2", text: "wevtutil cl Security run by hand, leaving a lone Event 1102 and no other admin activity around it", bucket: "sig", why: "Clearing the Security log outside maintenance is close to unambiguous, and the 1102 it leaves is your timestamp for where else to look." },
          { id: "s3", text: "Set-MpPreference -DisableRealtimeMonitoring $true run from a user context mid-shift", bucket: "sig", why: "Turning off Defender real-time protection outside a controlled change is a security-tooling disable, a hallmark of this stage." },
        ],
      },
    ],

    // ── Reading 7: exfiltration-first model ──────────────────────────────────
    "rw-r7": [
      {
        kind: "sequence",
        title: "The order of operations moved",
        prompt: "Reading 7 says staging and exfiltration now routinely happen BEFORE encryption. Tap the current-model stages in order, from foothold to note.",
        items: [
          { id: "a", text: "Foothold, full AD recon and credential access" },
          { id: "b", text: "Stage archives and exfiltrate the real payload (hours to days)" },
          { id: "c", text: "Encrypt fleet-wide, days later" },
          { id: "d", text: "Drop the note, referencing already-published leak-site proof" },
        ],
        order: ["a", "b", "c", "d"],
        doneNote: "A well-organised affiliate banks the leverage before risking the detection the noisy, obviously destructive encryption stage almost guarantees. 'No files encrypted yet' is not 'we are safe'.",
      },
      {
        kind: "sort",
        title: "Staging leaves a trail",
        prompt: "Before data leaves, it is usually archived, then pushed with a transfer tool. Sort these into archive-staging signals and the transfer step.",
        buckets: [
          { id: "arch", label: "Archive-staging signal" },
          { id: "xfer", label: "The transfer tool" },
        ],
        items: [
          { id: "7z", text: "A burst of .7z or .rar files appears in a share that never held any before", bucket: "arch", why: "7-Zip or WinRAR compressing a target directory into a handful of large files is itself a detectable pattern." },
          { id: "mega", text: "MEGAcmd copies a staged archive out to cloud storage", bucket: "xfer", why: "MEGAcmd and rclone are the two most consistently observed transfer tools; the cloud variant is ATT&CK T1567.002." },
          { id: "winscp", text: "WinSCP pushes the archive to an external host", bucket: "xfer", why: "WinSCP, rsync and abuse of an installed sync client all appear as the transfer step too." },
          { id: "big", text: "A single directory suddenly holds a few unusually large files just before an outbound spike", bucket: "arch", why: "The compression into a handful of large files is the staging tell that precedes the push." },
        ],
      },
      {
        kind: "simulate",
        title: "When does acting still change the outcome?",
        prompt: "Pick a moment to intervene and see whether it still changes how the story ends. Try both.",
        checks: [
          { name: "Availability", question: "Can you still prevent the loss of availability?" },
          { name: "Leverage", question: "Can you still stop the stolen data from leaving?" },
        ],
        scenarios: [
          {
            id: "staging",
            label: "During exfiltration staging",
            detail: "A large, anomalous outbound transfer is in progress; nothing has been encrypted yet.",
            results: ["pass", "pass"],
            why: ["Encryption has not started, so availability is still protectable.", "Cutting the transfer now can mean the leverage the attacker was counting on never leaves the building."],
            verdict: "Often the last point where acting genuinely changes the outcome. This is why the exfiltration log analysis sits here, not at encryption.",
          },
          {
            id: "afterenc",
            label: "After encryption has started",
            detail: "The encryptor is already running fleet-wide.",
            results: ["fail", "pass"],
            why: ["Once encryption starts, the damage to availability is largely locked in regardless of what happens next.", "You can still contain and still matter, but the highest-value window has passed."],
            verdict: "Still worth acting, but the exfiltration-staging window was the higher-value moment.",
          },
        ],
      },
    ],

    // ── Reading 8: impact, extortion & the playbook ─────────────────────────
    "rw-r8": [
      {
        kind: "sort",
        title: "Encryption facts, straight",
        prompt: "Reading 8 explains how production ransomware encryption actually works. Sort each statement as true or false.",
        buckets: [
          { id: "true", label: "True" },
          { id: "false", label: "False" },
        ],
        items: [
          { id: "t1", text: "A fast symmetric cipher (AES or ChaCha20) encrypts file contents, and an asymmetric public key wraps the symmetric key", bucket: "true", why: "This hybrid scheme is why it is both fast at scale and hard to reverse." },
          { id: "t2", text: "The matching private key never touches the victim's environment", bucket: "true", why: "It exists only on the attacker's infrastructure, which is why 'recover the key from memory' almost never works at scale." },
          { id: "f1", text: "Free public decryptors are common because the underlying cryptography is usually weak", bucket: "false", why: "They are rare, and exist only from an implementation flaw in one family's build or a law-enforcement key seizure, not a broken cipher." },
          { id: "f2", text: "Renaming the encryptor binary defeats modern EDR detection of the impact stage", bucket: "false", why: "EDR watches the rename-rate spike as a behavioural signature independent of the binary's name, so disguising the name slows detection but does not defeat it." },
        ],
      },
      {
        kind: "match",
        title: "Each stage, the analyst's move",
        prompt: "The full-chain playbook pairs a detection point with an action. Match each stage to what the SOC does there.",
        pairs: [
          { id: "ia", left: "Initial Access", right: "Contain the account/session; patch or isolate the exploited entry point", why: "Close the actual door, not just the symptom." },
          { id: "cred", left: "Discovery / Credential Access", right: "Treat reachable credentials as compromised; disable the exposed privileged accounts now", why: "Disabling the known-stolen accounts is containment and does not wait; the full rotation comes after eradication." },
          { id: "exfil", left: "Exfiltration", right: "Cut external network access for the host now", why: "The highest-value stage left to actually change the outcome." },
          { id: "impact", left: "Impact", right: "Isolate every affected and targeted host; hunt the push; hand facts, not decisions, to IR", why: "Scope by the deployment push, not only the hosts where the encryptor fired." },
        ],
      },
      {
        kind: "sort",
        title: "Whose call is it?",
        prompt: "Reading 8 closes on the governance line. Sort each decision by who owns it.",
        buckets: [
          { id: "soc", label: "The SOC owns it" },
          { id: "exec", label: "Leadership, legal, insurer own it" },
        ],
        items: [
          { id: "facts", text: "Produce the facts: what got in, what was touched, what was taken, what is still spreading", bucket: "soc", why: "Producing those facts quickly and accurately is the SOC's job through every stage." },
          { id: "scope", text: "Isolate, scope and preserve evidence of the active intrusion", bucket: "soc", why: "Containment and scoping are squarely the SOC's work." },
          { id: "pay", text: "Decide whether to pay the ransom", bucket: "exec", why: "A decision for executive leadership, legal counsel and often the cyber insurer, with real regulatory and sanctions considerations." },
          { id: "notify", text: "Report to law enforcement and notify regulators and affected people of a data breach", bucket: "exec", why: "The external obligations belong to the same leadership and legal owners, not the SOC." },
        ],
      },
    ],
  },
};
