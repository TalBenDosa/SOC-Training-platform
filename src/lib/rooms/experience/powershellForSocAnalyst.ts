import type { RoomExperience } from "./types";

// "Operation Same Shell" for the "powershell-for-soc-analyst" room.
// Script: docs/campaign/31-powershell-for-soc-analyst.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Corrin Foods (fictional), not the graded tasks' CORP. Lab data differs from
// the graded tasks: the pipeline console never asks what the CPU column means
// (q1); the cmdlet console never runs Get-LocalGroupMember (q2) or
// Get-NetTCPConnection (q3, qf1); the PID pivot starts from a PID the EDR
// already named, never from a connection's owning process (qf1); and the task
// sheet is a root-folder task authored by a contractor, never a task filed
// under \Microsoft\Windows\ (la1) or a script in C:\Users\Public (flag1).
export const POWERSHELL_FOR_SOC_ANALYST: RoomExperience = {
  roomId: "powershell-for-soc-analyst",
  codename: "Operation Same Shell",
  theme: "powershell",
  handler: { name: "Tomás Ibarra", role: "Senior SOC Analyst, Corrin Foods" },
  briefing: [
    "Corrin Foods. Four bakeries, two cold-storage depots, and 900 Windows machines that keep the ovens and the trucks on schedule.",
    "Every week the SOC sees PowerShell used against it: encoded commands, hidden windows, downloads from nowhere.",
    "Tomás Ibarra runs the second tier. He investigates with the very same shell, and he wants you to as well.",
    "Learn to tell the analyst from the attacker, chain cmdlets into evidence, pivot from a PID to a binary, and hunt a task nobody recognises.",
  ],
  mission: "Separate analyst PowerShell from attacker PowerShell by context, build an investigative pipeline step by step, run the core cmdlets on a live host, pivot an EDR PID into a path, a command line and a hash, and read a scheduled-task sweep for the one that doesn't belong.",
  estimate: "~40 min",
  look: { primary: "#38bdf8", secondary: "#facc15", warn: "#f43f5e" },
  scene: "objectpipe",
  layout: "stage",
  stations: [
    {
      id: "context",
      label: "Same Binary",
      topic: "Dual-use tools · context, not the cmdlet, tells you who is typing",
      tagline: "Tell the analyst from the attacker",
      building: "control",
      taskIds: ["ps-soc-r1"],
    },
    {
      id: "pipeline",
      label: "The Pipeline",
      topic: "Objects, not text · Where-Object, Select-Object, Sort-Object, Export-Csv",
      tagline: "Build an investigation one pipe at a time",
      building: "lab",
      taskIds: ["ps-soc-r2"],
    },
    {
      id: "cmdlets",
      label: "Seven Cmdlets",
      topic: "Process, service, event log, files and hashes, tasks, local groups",
      tagline: "Interrogate a live host",
      building: "office",
      taskIds: ["ps-soc-r3", "ps-soc-q1", "ps-soc-q2"],
    },
    {
      id: "pivot",
      label: "Follow the PID",
      topic: "From an alert to the process that holds it",
      tagline: "Pivot from a number to a binary",
      building: "vault",
      taskIds: ["ps-soc-q3", "ps-soc-qf1"],
    },
    {
      id: "hunt",
      label: "The Task Nobody Knows",
      topic: "Sweeping scheduled tasks · evidence before cleanup",
      tagline: "Hunt it, then collect it",
      building: "ticket",
      taskIds: ["ps-soc-la1", "ps-soc-match1", "ps-soc-flag1"],
      boss: true,
    },
  ],
  personas: {
    "ps-soc-q1": { name: "Tomás Ibarra", role: "Senior SOC Analyst", line: "svchost shows CPU 5400 on a 30-day server. Is it pegged right now?" },
    "ps-soc-q2": { name: "Tomás Ibarra", role: "Senior SOC Analyst", line: "The contractor left. Do they still have local admin on that box?" },
    "ps-soc-q3": { name: "Tomás Ibarra", role: "Senior SOC Analyst", line: "Port 4444 outbound and no process name. Which cmdlet do you reach for?" },
    "ps-soc-la1": { name: "Tomás Ibarra", role: "Senior SOC Analyst", line: "A task on a finance box that IT has never heard of. Read the 4698 with me." },
  },
  briefings: {
    // ── Reading 1: same binary, different context ──
    "ps-soc-r1": [
      {
        kind: "lineup",
        title: "Who Ran It?",
        prompt: "Same binary, same cmdlets, five possible operators. For each run in this morning's EDR feed, pick who was really at the keyboard.",
        suspects: [
          { id: "analyst", name: "SOC analyst", motive: "Investigating an alert", skill: "Visible console, own logon, explorer.exe parent", target: "Logs and processes" },
          { id: "sccm", name: "SCCM client", motive: "Scheduled maintenance", skill: "Runs as SYSTEM in the 02:00 window", target: "Services and patches" },
          { id: "helpdesk", name: "Helpdesk technician", motive: "Fixing a ticket", skill: "Remote session tied to an open ticket", target: "One user's files" },
          { id: "macro", name: "Malicious macro", motive: "First foothold", skill: "Hidden window started by an Office app", target: "Discovery, then download" },
          { id: "implant", name: "WMI implant", motive: "Staying in", skill: "Encoded commands launched through wmiprvse.exe at night", target: "Tasks and persistence" },
        ],
        rounds: [
          { id: "r1", evidence: ["Get-WinEvent in a visible console", "parent explorer.exe", "user on SOC-WS-03", "09:40"], suspect: "analyst", why: "Interactive, visible, on the analyst's own workstation and logon." },
          { id: "r2", evidence: ["Get-Process -WindowStyle Hidden", "parent EXCEL.EXE", "bakery-floor PC", "then a web request"], suspect: "macro", why: "A spreadsheet has no reason to start a hidden shell. Same cmdlet, wrong shape." },
          { id: "r3", evidence: ["Get-Service", "NT AUTHORITY\\SYSTEM", "CcmExec.exe parent", "02:03"], suspect: "sccm", why: "A known management agent at its scheduled time." },
          { id: "r4", evidence: ["Get-ScheduledTask inside -EncodedCommand", "parent wmiprvse.exe", "03:12"], suspect: "implant", why: "Encoded, launched through WMI, in the middle of the night." },
          { id: "r5", evidence: ["Get-ChildItem C:\\Users\\Public", "remote session", "ticket INC-58214 open"], suspect: "helpdesk", why: "Visible, ticketed, by staff whose job it is." },
        ],
      },
    ],
    // ── Reading 2: the pipeline ──
    "ps-soc-r2": [
      {
        kind: "terminal",
        title: "Build the Pipeline",
        prompt: "OVEN-CTL-02 runs a bakery line. Build the investigation one pipe at a time: list, filter, trim, sort, export.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "^get-process\\s*$", help: "Get-Process   every process, every property",
            output: "Handles  NPM(K)  PM(K)   WS(K)   CPU(s)     Id  ProcessName\n-------  ------  -----   -----   ------     --  -----------\n    412      24   9120   18440     2.11   1180  conhost\n   1290      61  88412  120332   412.55   2240  OvenHMI\n    233      14   4410   11020    14.02   3302  rdpclip\n    880      40  61200   90020   188.40   4416  svchost\n    655      33  48812   61880   933.71   6120  msupdsvc\n   2104     102 204400  301228    96.30   7012  explorer\n   ... 58 more" },
          { match: "^get-process\\s*\\|\\s*(where-object|where|\\?)\\s*\\{?\\s*\\$_\\.cpu\\s+-gt\\s+100\\s*\\}?\\s*$", help: "Get-Process | Where-Object {$_.CPU -gt 100}   keep only the busy ones",
            output: "Handles  NPM(K)  PM(K)   WS(K)   CPU(s)     Id  ProcessName\n-------  ------  -----   -----   ------     --  -----------\n   1290      61  88412  120332   412.55   2240  OvenHMI\n    880      40  61200   90020   188.40   4416  svchost\n    655      33  48812   61880   933.71   6120  msupdsvc" },
          { match: "^get-process\\s*\\|\\s*(where-object|where|\\?)\\s*\\{?\\s*\\$_\\.cpu\\s+-gt\\s+100\\s*\\}?\\s*\\|\\s*(select-object|select)\\s+name\\s*,\\s*id\\s*,\\s*(cpu\\s*,\\s*path|path\\s*,\\s*cpu)\\s*$", help: "... | Select-Object Name, Id, CPU, Path   trim to what matters",
            output: "Name     Id     CPU Path\n----     --     --- ----\nOvenHMI  2240  412.55 C:\\Program Files\\Corrin\\OvenHMI\\OvenHMI.exe\nsvchost  4416  188.40 C:\\Windows\\System32\\svchost.exe\nmsupdsvc 6120  933.71 C:\\ProgramData\\msupd\\msupdsvc.exe" },
          { match: ".*\\|\\s*(sort-object|sort)\\s+cpu\\s+-desc\\w*\\s*$", help: "... | Sort-Object CPU -Descending   biggest first",
            output: "Name     Id     CPU Path\n----     --     --- ----\nmsupdsvc 6120  933.71 C:\\ProgramData\\msupd\\msupdsvc.exe\nOvenHMI  2240  412.55 C:\\Program Files\\Corrin\\OvenHMI\\OvenHMI.exe\nsvchost  4416  188.40 C:\\Windows\\System32\\svchost.exe" },
          { match: ".*\\|\\s*export-csv\\s+(\\S+\\.csv).*", help: "... | Export-Csv oven02_busy.csv -NoTypeInformation   turn it into evidence",
            output: "(no output: 3 objects written to C:\\oven02_busy.csv)" },
          { match: "^(get-content|gc|type|cat)\\s+.*\\.csv\\s*$", help: "Get-Content oven02_busy.csv   check what you exported",
            output: "\"Name\",\"Id\",\"CPU\",\"Path\"\n\"msupdsvc\",\"6120\",\"933.71\",\"C:\\ProgramData\\msupd\\msupdsvc.exe\"\n\"OvenHMI\",\"2240\",\"412.55\",\"C:\\Program Files\\Corrin\\OvenHMI\\OvenHMI.exe\"\n\"svchost\",\"4416\",\"188.40\",\"C:\\Windows\\System32\\svchost.exe\"" },
        ],
        objectives: [
          { id: "count", task: "How many processes pass the CPU filter?", hint: "Get-Process | Where-Object {$_.CPU -gt 100}", answer: ["3", "three"], why: "Three objects survive the filter; the other 61 never reach the next pipe." },
          { id: "odd", task: "Add Select-Object Name, Id, CPU, Path. Which process lives somewhere it shouldn't?", hint: "... | Select-Object Name, Id, CPU, Path", answer: ["msupdsvc", "msupdsvc.exe"], why: "A 'Microsoft update' name running from ProgramData, not System32 or Program Files. Path is a property you only see because you selected it." },
          { id: "file", task: "Sort it and export it. Which line of the CSV comes first after the header? (process name)", hint: "... | Sort-Object CPU -Descending | Export-Csv oven02_busy.csv -NoTypeInformation, then Get-Content", answer: ["msupdsvc"], why: "Sorted before export, so the CSV the incident lead opens starts with the process that matters." },
        ],
      },
    ],
    // ── Reading 3: the core cmdlets ──
    "ps-soc-r3": [
      {
        kind: "terminal",
        title: "Interrogate the Host",
        prompt: "Still on OVEN-CTL-02. Use the core cmdlets to check the defences, the dropped files and the logon failures.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-service\\s+.*(windefend|sense|defender).*", help: "Get-Service WinDefend, Sense   are the defences running?",
            output: "Status   Name       DisplayName\n------   ----       -----------\nStopped  WinDefend  Microsoft Defender Antivirus Service\nRunning  Sense      Windows Defender Advanced Threat Protection Service" },
          { match: "get-childitem\\s+.*programdata.msupd.*", help: "Get-ChildItem C:\\ProgramData\\msupd   what was dropped",
            output: "    Directory: C:\\ProgramData\\msupd\n\nMode   LastWriteTime        Length Name\n----   -------------        ------ ----\n-a---  11/03/2026  21:58   184320 msupdsvc.exe\n-a---  11/03/2026  21:58      412 cfg.dat" },
          { match: "get-filehash\\s+.*msupdsvc\\.exe.*", help: "Get-FileHash C:\\ProgramData\\msupd\\msupdsvc.exe   SHA256 for the ticket",
            output: "Algorithm  Hash                                                              Path\n---------  ----                                                              ----\nSHA256     9c4e2b7a1f08d35e6b0a4c91d2e7f5038a6b1c4d9e2f70a8b3c5d6e1f2a4b7c9  C:\\ProgramData\\msupd\\msupdsvc.exe" },
          { match: "get-winevent\\s+-filterhashtable\\s+.*4625.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)}",
            output: "TimeCreated            Id  Message\n-----------            --  -------\n11/03/2026 21:52:41  4625  An account failed to log on. ... Account Name: ovenadmin ... Source Network Address: 10.40.2.77\n11/03/2026 21:52:39  4625  An account failed to log on. ... Account Name: ovenadmin ... Source Network Address: 10.40.2.77\n11/03/2026 21:52:36  4625  An account failed to log on. ... Account Name: ovenadmin ... Source Network Address: 10.40.2.77\n(3 events)" },
          { match: "get-winevent\\s+-filterhashtable\\s+.*4624.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} | select -First 1",
            output: "TimeCreated            Id  Message\n-----------            --  -------\n11/03/2026 21:53:10  4624  An account was successfully logged on. ... Logon Type: 3 ... Account Name: ovenadmin ... Source Network Address: 10.40.2.77" },
        ],
        objectives: [
          { id: "av", task: "Which defence is stopped?", hint: "Get-Service WinDefend, Sense", answer: ["windefend", "microsoft defender antivirus", "defender antivirus"], why: "WinDefend stopped while the EDR sensor still runs. Someone turned off the antivirus, not the telemetry." },
          { id: "when", task: "What time was msupdsvc.exe written? (HH:MM)", hint: "Get-ChildItem C:\\ProgramData\\msupd", answer: ["21:58"], why: "Five minutes after the logon from 10.40.2.77. Record the hash before anyone moves the file." },
          { id: "src", task: "Which address failed three times and then got in?", hint: "Get-WinEvent with Id 4625, then Id 4624", answer: ["10.40.2.77"], why: "Three failures at 21:52, a network logon at 21:53, a dropped binary at 21:58: one timeline from three cmdlets." },
        ],
      },
    ],
    // ── The pivot, before the graded query ──
    "ps-soc-qf1": [
      {
        kind: "terminal",
        title: "From PID to Binary",
        prompt: "A different alert: Defender for Endpoint already names PID 6120 on OVEN-CTL-02. Turn that number into a path, a parent, a command line and a signature.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-process\\s+-id\\s+6120.*", help: "Get-Process -Id 6120 | Select-Object Name, Path, StartTime",
            output: "Name     Path                                 StartTime\n----     ----                                 ---------\nmsupdsvc C:\\ProgramData\\msupd\\msupdsvc.exe  11/03/2026 21:59:02" },
          { match: "get-(cim|wmi)\\w*\\s+.*win32_process.*6120.*", help: "Get-CimInstance Win32_Process -Filter \"ProcessId=6120\" | Select-Object ParentProcessId, CommandLine",
            output: "ParentProcessId CommandLine\n--------------- -----------\n           4416 \"C:\\ProgramData\\msupd\\msupdsvc.exe\" -k netsvcs -cfg cfg.dat" },
          { match: "get-process\\s+-id\\s+4416.*", help: "Get-Process -Id 4416   who started it",
            output: "Handles  NPM(K)  PM(K)   WS(K)   CPU(s)     Id  ProcessName\n-------  ------  -----   -----   ------     --  -----------\n    880      40  61200   90020   188.40   4416  svchost" },
          { match: "get-authenticodesignature\\s+.*msupdsvc.*", help: "Get-AuthenticodeSignature C:\\ProgramData\\msupd\\msupdsvc.exe",
            output: "SignerCertificate  Status     Path\n-----------------  ------     ----\n                   NotSigned  msupdsvc.exe" },
        ],
        objectives: [
          { id: "parent", task: "Which process started PID 6120? (name)", hint: "Get-CimInstance Win32_Process ... ParentProcessId, then Get-Process -Id on that", answer: ["svchost", "svchost.exe"], why: "Started by svchost: it was installed to run as a service, not launched by a user." },
          { id: "sig", task: "Is the binary signed?", hint: "Get-AuthenticodeSignature", answer: ["no", "notsigned", "not signed"], why: "An unsigned 'Microsoft update service' in ProgramData. Three facts, no guesswork." },
        ],
      },
    ],
    // ── Boss: a sweep before the graded 4698 ──
    "ps-soc-la1": [
      {
        kind: "worksheet",
        title: "Sweep the Depot",
        prompt: "Tomás ran a first-pass task sweep on DEPOT-PC-07 at the cold-storage depot. Read the result before you open the graded record.",
        caption: "Get-ScheduledTask | Select-Object TaskPath, TaskName, Author, State · DEPOT-PC-07",
        columns: ["TaskPath", "TaskName", "Author", "State", "Action"],
        rows: [
          ["\\Microsoft\\Windows\\Defrag\\", "ScheduledDefrag", "Microsoft Corporation", "Ready", "%windir%\\system32\\defrag.exe -c -h -o"],
          ["\\Corrin\\", "FleetTelemetryUpload", "CORRIN\\svc-fleet", "Ready", "C:\\Program Files\\Corrin\\Fleet\\upload.exe"],
          ["\\", "TempSensorSync", "CORRIN\\ext.dvorak", "Running", "wscript.exe C:\\Users\\ext.dvorak\\AppData\\Local\\tss\\sync.vbs"],
          ["\\Microsoft\\Windows\\UpdateOrchestrator\\", "Schedule Scan", "Microsoft Corporation", "Ready", "%systemroot%\\system32\\usoclient.exe StartScan"],
        ],
        questions: [
          { id: "odd", q: "Which task needs follow-up? (TaskName)", hint: "Author and action together.", answer: ["tempsensorsync"], why: "A contractor-authored task in the root folder, running a VBScript from the contractor's own profile. FleetTelemetryUpload is a service account running a signed vendor path." },
          { id: "who", q: "Which account registered it?", hint: "The Author column.", answer: ["ext.dvorak", "corrin\\ext.dvorak"], why: "A contractor account. Is the engagement still active, and does the depot use temperature-sensor scripts at all? Ask the people who would know, not the account itself." },
        ],
      },
    ],
  },
};
