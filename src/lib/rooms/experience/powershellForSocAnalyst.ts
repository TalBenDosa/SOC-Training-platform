import type { RoomExperience } from "./types";

// "Operation Same Shell" for the "powershell-for-soc-analyst" room.
// Script: docs/campaign/31-powershell-for-soc-analyst.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Corrin Foods (fictional), not the graded tasks' CORP. Lab data differs from
// the graded tasks: the console reads current load for OvenHMI, not a svchost on
// a file server (q1); it runs Get-LocalGroupMember on Remote Desktop Users, not
// Administrators (q2), and Get-NetTCPConnection on a listening port, not an
// established connection to 4444 (q3, qf1); the PID pivot starts from a PID the EDR
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
  story: {
    intro: { title: "Same Shell", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-intro-1d1d445e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-intro-5edda611.jpg" },
    afterStation: {
      pipeline: { title: "Objects, Not Text", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-ch2-400a9c51.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-ch2-d7ed2729.jpg" },
      cmdlets: { title: "PID 6120", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-ch3-e2cd63e4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-ch3-77228455.jpg" },
      hunt: { title: "Collect, Then Remove", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-finale-be62dd32.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/powershell-for-soc-analyst/sameshell-finale-4c12b1ae.jpg" },
    },
  },
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
        prompt: "OVEN-CTL-02 runs a bakery line. Build the investigation one pipe at a time: list, filter, trim, sort, export. Then ask the host three direct questions: load now, group members, and who owns a port.",
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
          { match: "^get-counter\\s+['\"]?\\\\process\\(ovenhmi\\)\\\\% processor time['\"]?\\s*$", help: "Get-Counter '\\Process(OvenHMI)\\% Processor Time'   sample one process's load right now",
            output: "Timestamp                 CounterSamples\n---------                 --------------\n11/06/2026 02:14:08       \\\\oven-ctl-02\\process(ovenhmi)\\% processor time :\n                          0.38" },
          { match: "^get-localgroupmember\\s+(-group\\s+)?['\"]remote desktop users['\"]\\s*$", help: "Get-LocalGroupMember -Group \"Remote Desktop Users\"   who is in a local group on this host",
            output: "ObjectClass Name                 PrincipalSource\n----------- ----                 ---------------\nGroup       CORRIN\\Line-Engineers ActiveDirectory\nUser        OVEN-CTL-02\\ovenvendor Local" },
          { match: "^get-nettcpconnection(\\s+-state\\s+listen)?\\s+-localport\\s+8080\\s*$", help: "Get-NetTCPConnection -State Listen -LocalPort 8080   who holds this port",
            output: "LocalAddress  LocalPort RemoteAddress RemotePort State  OwningProcess\n------------  --------- ------------- ---------- -----  -------------\n0.0.0.0       8080      0.0.0.0       0          Listen 6120" },
          { match: "^get-process\\s+-id\\s+6120\\s*$", help: "Get-Process -Id 6120   turn a PID into a process",
            output: "Handles  NPM(K)  PM(K)   WS(K)   CPU(s)     Id  ProcessName\n-------  ------  -----   -----   ------     --  -----------\n    655      33  48812   61880   933.71   6120  msupdsvc" },
        ],
        objectives: [
          { id: "count", task: "How many processes pass the CPU filter?", hint: "Get-Process | Where-Object {$_.CPU -gt 100}", answer: ["3", "three"], why: "Three objects survive the filter; the other 61 never reach the next pipe." },
          { id: "odd", task: "Add Select-Object Name, Id, CPU, Path. Which process lives somewhere it shouldn't?", hint: "... | Select-Object Name, Id, CPU, Path", answer: ["msupdsvc", "msupdsvc.exe"], why: "A 'Microsoft update' name running from ProgramData, not System32 or Program Files. Path is a property you only see because you selected it." },
          { id: "file", task: "Sort it and export it. Which line of the CSV comes first after the header? (process name)", hint: "... | Sort-Object CPU -Descending | Export-Csv oven02_busy.csv -NoTypeInformation, then Get-Content", answer: ["msupdsvc"], why: "Sorted before export, so the CSV the incident lead opens starts with the process that matters." },
          { id: "load", task: "The line is idle tonight, yet OvenHMI's CPU(s) says 412.55. Sample it directly. What % Processor Time does it show right now?", hint: "Get-Counter '\\Process(OvenHMI)\\% Processor Time'", answer: ["0.38", ".38"], why: "CPU(s) is a running total: every second of processor work the process has done, added up over the nine days it has been open. A big number only says it has been alive a long time. Get-Counter samples the moment you ask." },
          { id: "group", task: "The oven vendor's contract ended in September. Which Local account can still Remote Desktop into this host?", hint: "Get-LocalGroupMember -Group \"Remote Desktop Users\"", answer: ["ovenvendor", "OVEN-CTL-02\\ovenvendor"], why: "Get-LocalGroupMember reads who belongs to a local group on this machine, nested domain groups included. PrincipalSource tells you which entries live on the host and which come from the domain." },
          { id: "port", task: "Something on an oven controller is listening on 8080. Which process owns the port? Pivot from the connection to the process name.", hint: "Get-NetTCPConnection -State Listen -LocalPort 8080, then Get-Process -Id with the number you find", answer: ["msupdsvc", "msupdsvc.exe"], why: "OwningProcess is the PID behind a socket, and Get-Process -Id turns it into a name and path. -State decides which sockets you see: Listen is a port waiting for callers, and other states show connections at other points in their life." },
        ],
      },
    ],
    // ── Reading 3: the core cmdlets ──
    "ps-soc-r3": [
      {
        kind: "codebreak",
        title: "Name That Cmdlet",
        prompt: "Still on OVEN-CTL-02. Tomás reads out what he needs from the host and you name the piece of the toolkit that gets it. Give the noun of the cmdlet, or the event ID.",
        tries: 6,
        rounds: [
          { id: "svc", clue: "He wants to know whether WinDefend is Running or Stopped, and whether the EDR sensor service still is. Get-what? One word, the noun.", answer: "SERVICE", why: "Get-Service lists status by name. WinDefend stopped while the EDR sensor still runs means someone turned off the antivirus, not the telemetry." },
          { id: "hash", clue: "A binary was dropped in ProgramData and Tomás needs a SHA256 for the ticket before anyone moves it. Get-what? One word.", answer: "FILEHASH", why: "Get-FileHash gives the fingerprint to look up and to hunt across the fleet. Take it before the file changes. Get-ChildItem on the folder gives the write time to line up with the logons." },
          { id: "evt", clue: "He wants Security log records between two times, filtered by event ID, without scrolling the whole log. Get-what? The noun of the cmdlet that reads event logs.", answer: "WINEVENT", why: "Get-WinEvent with a filter hashtable asks the log for only the IDs and times you need, which is far faster than piping everything to Where-Object." },
          { id: "fail", clue: "Three of these from one address at 21:52, then a successful network logon at 21:53 and a file written at 21:58. Event ID for the failed logon?", answer: "4625", why: "4625 is the failed logon. Failures from one address followed by a success from the same address, then a dropped file: one timeline from three cmdlets." },
        ],
        lesson: "Each cmdlet answers one question: Get-Service for state, Get-FileHash for a fingerprint, Get-WinEvent with a filter for the log, and an event ID to match. Line their timestamps up before you write the story.",
      },
    ],
    // ── The pivot, before the graded query ──
    "ps-soc-qf1": [
      {
        kind: "spotdiff",
        title: "Two Hosts, One Service Name",
        prompt: "An alert names PID 7204 on OVEN-CTL-05, a service called CorrinSchedSvc. Tomás pulls the same property sheet from a healthy bakery host (path, parent, command line, signature, start time) and puts them side by side. Tap what the pivot proves; start-up noise is not a finding.",
        goodTitle: "OVEN-CTL-01 · healthy · PID 3188",
        suspectTitle: "OVEN-CTL-05 · alert · PID 7204",
        good: [
          "Name            CorrinSchedSvc",
          "Id              3188",
          "Path            C:\\Program Files\\Corrin\\Scheduler\\schedsvc.exe",
          "StartTime       11/03/2026 06:00:14",
          "ParentProcessId 744 (services.exe)",
          "CommandLine     \"C:\\Program Files\\Corrin\\Scheduler\\schedsvc.exe\" --service",
          "Company         Corrin Foods",
          "SignatureStatus Valid",
          "FileVersion     4.2.1",
          "ProductName     Corrin Scheduler",
          "Owner           NT AUTHORITY\\SYSTEM",
          "Handles         412",
        ],
        suspect: [
          "Name            CorrinSchedSvc",
          "Id              7204",
          "Path            C:\\ProgramData\\Corrin\\schedsvc.exe",
          "StartTime       11/03/2026 21:59:02",
          "ParentProcessId 744 (services.exe)",
          "CommandLine     \"C:\\ProgramData\\Corrin\\schedsvc.exe\" --service -cfg cfg.dat",
          "Company         Corrin Foods",
          "SignatureStatus NotSigned",
          "FileVersion     4.2.1",
          "ProductName     Corrin Scheduler",
          "Owner           NT AUTHORITY\\SYSTEM",
          "Handles         412",
        ],
        diffs: [
          { line: 2, why: "Same name, wrong folder. The real scheduler lives under Program Files, where writing needs admin. Get-Process shows the Path property; a name alone proves nothing." },
          { line: 5, why: "Get-CimInstance Win32_Process shows the command line: it runs from the same ProgramData folder and reads a config file the real service never takes. Parent services.exe only tells you it was installed as a service." },
          { line: 7, why: "Get-AuthenticodeSignature returns NotSigned where the real file is Valid. Company and ProductName are plain text anyone can set, so only the signature settles it; the file hash is the next pivot." },
        ],
        decoys: [
          { line: 1, why: "A PID changes every time the process starts, so different numbers on two hosts mean nothing." },
          { line: 3, why: "Start times reflect when each host booted or restarted the service. Compare it to the install and logon timeline of this host, not to another host." },
        ],
        lesson: "Turn a PID into four facts: path (Get-Process), parent and command line (Get-CimInstance Win32_Process), and signature (Get-AuthenticodeSignature). Compare them to a healthy host and ignore the properties that always differ.",
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
