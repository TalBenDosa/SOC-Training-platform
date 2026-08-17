/**
 * Learning Rooms — Batch 31
 *
 * One room: "PowerShell for the SOC Analyst" — the defender's side of a tool
 * this platform has, until now, only taught from the attacker's side
 * (windows-fundamentals covers -EncodedCommand, execution-policy bypass, and
 * winword.exe -> powershell.exe as an initial-access chain; several other
 * rooms show PowerShell as a LOLBin). This room closes that gap: the same
 * binary, used the other way — Get-Process, Get-Service, Get-WinEvent,
 * Get-ChildItem, Get-NetTCPConnection, Get-ScheduledTask, and
 * Get-LocalGroupMember, chained through the object pipeline with
 * Where-Object, Select-Object, Sort-Object, and Export-Csv, to actually run
 * an investigation.
 *
 * Design constraint honoured throughout: no raw log field states a verdict.
 * The scheduled-task record in the log_analysis task carries only real
 * Windows Security (Event ID 4698) fields; the suspicion is carried by
 * observable facts (a standard user's SID as the task author, a Hidden
 * window flag, a world-writable staging folder, an off-hours trigger time)
 * — never by a field or value that announces itself as malicious.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// ---------------------------------------------------------------------------
// Event — Windows Security Event ID 4698 (scheduled task created), the
// record the analyst pulls up after finding the same task live on the host
// with Get-ScheduledTask.
// ---------------------------------------------------------------------------

const scheduledTaskEvent: TelemetryEvent = {
  id: "evt-ps-soc-la1-001",
  ts: "2026-08-11T23:47:03Z",
  source: "windows_security",
  vendor: "Microsoft Windows Security Auditing",
  event_type: "scheduled_task",
  severity: "high",
  hostname: "CORP-FIN-014",
  description:
    "A new scheduled task was registered on a finance workstation outside normal business hours. This is the Windows Security log record (Event ID 4698) matching the task an analyst had already found live on the host while sweeping it with Get-ScheduledTask.",
  raw: {
    "winlog.event_id": "4698",
    "winlog.channel": "Security",
    "winlog.computer_name": "CORP-FIN-014.corp.local",
    "winlog.event_data.SubjectUserSid": "S-1-5-21-2839104451-1699999903-129877423-1147",
    "winlog.event_data.SubjectUserName": "j.alvarez",
    "winlog.event_data.SubjectDomainName": "CORP",
    "winlog.event_data.SubjectLogonId": "0x3a9f21",
    "winlog.event_data.TaskName": "\\Microsoft\\Windows\\WindowsUpdate\\SystemHealthCheck",
    "winlog.event_data.TaskContent":
      '<Task version="1.4"><RegistrationInfo><Author>CORP\\j.alvarez</Author></RegistrationInfo><Principals><Principal id="Author"><UserId>S-1-5-21-2839104451-1699999903-129877423-1147</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Triggers><TimeTrigger><StartBoundary>2026-08-11T23:47:00</StartBoundary></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command><Arguments>-WindowStyle Hidden -NoProfile -Command "IEX (Get-Content \'C:\\Users\\Public\\upd.ps1\' -Raw)"</Arguments></Exec></Actions></Task>',
    timestamp: "2026-08-11T23:47:03Z",
  },
};

// ---------------------------------------------------------------------------
// Room — PowerShell for the SOC Analyst
// ---------------------------------------------------------------------------

const powershellForSocRoom: Room = {
  id: "powershell-for-soc-analyst",
  title: "PowerShell for the SOC Analyst — The Defender's Side of the Same Tool",
  description:
    "You have already seen PowerShell used against you — encoded commands, execution-policy bypass, winword.exe spawning a payload downloader. This room teaches the other half: the seven cmdlets an analyst actually reaches for during an investigation, how the object pipeline chains them together, and how to turn a live query into evidence you can hand to an incident lead.",
  difficulty: "intermediate",
  category: "Endpoint Security",
  estimatedMinutes: 55,
  xp: 245,
  icon: "🛡️",
  prerequisites: ["windows-fundamentals"],
  tasks: [
    // -----------------------------------------------------------------------
    // Reading 1 — Dual-use framing
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "ps-soc-r1",
      heading: "PowerShell Is a Tool, Not a Threat: The Defender's Toolkit",
      content:
        "In windows-fundamentals you learned to read PowerShell as an attacker technique: a Base64 -EncodedCommand, a hidden window, an execution-policy bypass, winword.exe spawning powershell.exe as the second step of a phishing chain. That reading was correct, and those indicators are real. But it only ever showed you one side of the tool. Every one of those attacker capabilities — running a command non-interactively, reaching out to a remote host, reading and writing files, inspecting what is running on a machine — is also, line for line, exactly what an analyst needs to investigate an incident. PowerShell is not an attacker tool that defenders occasionally borrow. It is a general-purpose administration shell that both sides use for the same underlying reason: it is the most capable way to interrogate a Windows system from the command line, and it ships on every modern Windows box by default.\n\nThis is what security engineers call a dual-use tool: a piece of software with no inherent moral direction, whose classification as 'attacker' or 'defender' depends entirely on who is running it, against what, and why — not on anything different in the binary itself. PsExec, certutil, rundll32, and even a plain web browser are dual-use in the same sense. PowerShell is simply the most powerful and most common example, because Microsoft built it to be exactly that capable on purpose, for administrators.\n\nThink about what that phishing chain from windows-fundamentals actually needed PowerShell to do: download a remote file and run it, without writing anything obviously suspicious to disk first. Now think about a real investigative task: an analyst who suspects a workstation has an unauthorized scheduled task needs to enumerate every task on that host, filter out the ones signed by Microsoft, and export the rest to a CSV for the incident ticket. Different goal, same underlying primitive — query the system, filter down to what matters, act on the result. The attacker's one-liner and the analyst's investigative pipeline are both, technically, 'just PowerShell.'\n\nSo if the tool cannot tell you who is using it, what can? Two things, and this room is built around both. First, cmdlets: PowerShell ships hundreds of built-in commands (cmdlets, pronounced 'command-lets') purpose-built for administration and investigation — Get-Process, Get-Service, Get-WinEvent, Get-ChildItem, Get-NetTCPConnection, Get-ScheduledTask, Get-LocalGroupMember. None of the seven you will learn in this room appear anywhere in the attacker chain you already studied, because an attacker's goal (execute a payload quietly) and an analyst's goal (enumerate and evidence what is on a system) point at different cmdlets almost entirely. Second, context: exactly as the earlier room put it, a defender's Get-WinEvent call runs interactively, from a visible console, under the analyst's own logged-in credentials, against a known log — while an attacker's PowerShell often runs hidden, spawned from an unrelated parent process, reaching out to the internet. Same binary. Opposite shape of use.\n\nThe goal of this room is narrow and practical: give you the cmdlets, the pipeline habits, and the worked examples to actually run an investigation in PowerShell — not just recognize when someone else has abused it.",
      checkpoint: {
        question:
          "According to the reading, what is the single biggest difference between PowerShell used as a defender's tool and PowerShell used as an attacker's tool?",
        options: [
          "The defender's copy of powershell.exe is a separate, digitally signed binary that attackers cannot run",
          "Nothing in the binary or the command itself distinguishes them — the difference is context: who is running it, how visibly, and against what",
          "Defenders are only permitted to use PowerShell ISE, while attackers can only launch powershell.exe from cmd.exe",
          "Windows Defender automatically allows any PowerShell command run by an analyst and blocks every command run by anyone else",
        ],
        answer: 1,
        explanation:
          "The reading's core point is that PowerShell is a dual-use tool: the same binary, the same cmdlets, no built-in moral direction. What separates a legitimate investigation from an attack is context — an interactive session under the analyst's own credentials against a known log, versus a hidden window spawned from an unrelated parent process reaching out to the internet. There is no separate 'defender binary,' and Windows Defender does not treat PowerShell differently based on who launched it.",
      },
    },

    // -----------------------------------------------------------------------
    // Reading 2 — The pipeline
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "ps-soc-r2",
      heading: "The Pipeline: Chaining Cmdlets Into an Investigation",
      content:
        "A single cmdlet rarely answers an investigative question on its own. Get-Process lists every process on a box — hundreds of rows, almost all of them irrelevant to the one you actually care about. The real power shows up when you chain cmdlets together with the pipe operator, written as a single vertical bar between commands. This is the same idea you may already know from Linux shells, where a pipe passes one command's text output into the next command as input. PowerShell's pipe does something more useful: it passes structured objects, not printed text.\n\nEvery cmdlet that starts with 'Get-' returns live objects with real, named properties. Get-Process returns process objects with a Name property, a CPU property, an Id property, and more. When you pipe that output into another cmdlet, you are handing over those objects intact — properties and all — not a block of formatted text that the next command has to re-parse with string matching or regular expressions. This is the mechanical reason PowerShell scripting feels so different from batch scripting or classic Unix shell one-liners: you filter and reshape data by property name, directly, every time.\n\nThree cmdlets do almost all of the reshaping work in a typical investigative pipeline:\n\nWhere-Object filters the objects flowing through the pipeline down to the ones matching a condition. The special variable $_ inside the filter block means 'the current object.' Where-Object {$_.CPU -gt 100} keeps only the process objects whose CPU property is greater than 100 — nothing about parsing columns of text, just a direct comparison on a real property.\n\nSelect-Object narrows the objects down to specific properties, so the result is readable instead of a wall of every property a process object happens to carry. Select-Object Name, Id, CPU keeps exactly those three fields per object and drops the rest.\n\nSort-Object reorders the objects by a property — useful for putting the highest-CPU or most-recent items at the top of a long result set before you scroll through it.\n\nAnd at the end of an investigative pipeline, Export-Csv writes whatever objects are left to a CSV file on disk, turning a live query into a durable artifact — something you can attach to a ticket, hand to an incident lead, or open in a spreadsheet six months later during a compliance review.\n\nPut all four together and you get a complete, working investigative one-liner:\n\nGet-Process | Where-Object {$_.CPU -gt 100} | Select-Object Name, Id, CPU | Export-Csv suspicious_processes.csv -NoTypeInformation\n\nRead it left to right, the way it actually executes. Get-Process produces every running process as an object. The pipe hands those objects, unmodified, to Where-Object, which keeps only the ones whose CPU property exceeds 100. The pipe hands that smaller set to Select-Object, which trims each surviving object down to just Name, Id, and CPU. The pipe hands that trimmed set to Export-Csv, which writes it to suspicious_processes.csv. The -NoTypeInformation flag simply suppresses an extra header line PowerShell would otherwise add, which most spreadsheet tools do not expect. One line, four cmdlets, and a piece of evidence that did not exist a second before you ran it.\n\nThis chained, filter-then-select-then-export shape is not specific to processes. It is the same shape you will use to filter scheduled tasks down to the ones not authored by Microsoft, filter TCP connections down to a specific remote port, or filter event log entries down to a specific event ID and time window. Learn the shape once, and every cmdlet in the rest of this room slots into it.",
      codeExample:
        "Get-Process | Where-Object {$_.CPU -gt 100} | Select-Object Name, Id, CPU | Export-Csv suspicious_processes.csv -NoTypeInformation",
      checkpoint: {
        question:
          "In the reading's pipeline example, what does the pipe (|) between Get-Process and Where-Object actually pass along?",
        options: [
          "The full text that Get-Process printed to the console screen",
          "Live process objects, carrying real properties like Name, CPU, and Id, that Where-Object can filter directly",
          "Only the process names, converted into a single comma-separated line of text",
          "Nothing is passed — Where-Object silently re-runs Get-Process internally using its own filter",
        ],
        answer: 1,
        explanation:
          "PowerShell's pipe passes structured objects between cmdlets, not printed text. Get-Process emits process objects with real properties (Name, CPU, Id, and more), and Where-Object filters directly on those properties — no text parsing involved. This is the mechanical reason PowerShell pipelines are more reliable than text-based shell piping for filtering and reshaping data.",
      },
    },

    // -----------------------------------------------------------------------
    // Reading 3 — 7 cmdlets to know cold
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "ps-soc-r3",
      heading: "7 Cmdlets Every Analyst Should Know Cold",
      content:
        "These seven cmdlets cover the large majority of what an analyst actually reaches for during a live endpoint investigation. None of them require third-party tooling — every one ships with Windows.\n\nGet-Process — lists every running process, with PID, CPU usage, and memory. Your first stop when a ticket says 'this machine feels slow' or 'EDR flagged a process I don't recognize.' Pipe it through Where-Object {$_.Name -eq 'powershell'} to isolate every PowerShell instance running right now, or Sort-Object CPU -Descending to see what is consuming the most CPU at this moment.\n\nGet-Service — lists Windows services and their current state (Running, Stopped, Paused). Useful two ways: confirming a security service (like the EDR sensor or Windows Defender) is actually running and was not disabled, and spotting an unfamiliar service name that was not there during the last baseline. Get-Service | Where-Object {$_.Status -eq 'Running'} narrows a long list down to what is actually active.\n\nGet-WinEvent (and its older, slower sibling Get-EventLog) — queries the Windows Event Log directly from the command line, without opening Event Viewer. This is the cmdlet you reach for constantly: pulling every failed logon (Event ID 4625) in the last hour, every process-creation event (4688), or every scheduled-task-created event (4698) tied to a specific host. Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)} filters at the source instead of pulling the entire log and searching through it afterward — which matters on a busy domain controller where the Security log can hold hundreds of thousands of entries.\n\nGet-ChildItem — PowerShell's equivalent of dir or ls: lists files and folders. Investigatively useful for checking what has been dropped into %TEMP%, %APPDATA%, or C:\\Users\\Public — the same user-writable, rarely-audited locations attackers favor for staging payloads, precisely because a standard user can write there without needing elevation.\n\nGet-NetTCPConnection — lists live TCP connections on the host, including local and remote address, remote port, connection state, and an OwningProcess property holding the PID that owns each connection. This is how you go from 'EDR flagged an outbound connection to an unfamiliar IP' to 'here is the exact process holding that connection open' — filter by -State Established and the remote port named in the alert, then pivot the OwningProcess value straight into Get-Process -Id to see the actual executable.\n\nGet-ScheduledTask — lists every scheduled task registered on the host, including its author and the folder path it lives under. Scheduled tasks are one of the most common persistence mechanisms, because a task set to run at logon or on a timer survives a reboot without needing a running process the whole time. Get-ScheduledTask | Where-Object {$_.Author -notlike '*Microsoft*'} is a fast first pass at separating built-in Windows tasks from everything else on the box.\n\nGet-LocalGroupMember — lists the members of a local group, most often -Group 'Administrators'. This is the cmdlet you reach for after any privilege-escalation concern: a helpdesk ticket about a former contractor, a suspicious group-membership change in a SIEM alert, or simply confirming that a workstation's local admin group matches what IT change control says it should.\n\nNone of these seven cmdlets require anything beyond what ships on a default Windows install, and every one of them slots into the pipeline pattern from the previous reading: query with the Get- cmdlet, narrow with Where-Object, trim with Select-Object, and — when the result needs to leave your session as evidence — write it out with Export-Csv.",
      checkpoint: {
        question:
          "Which of the seven cmdlets is the correct choice for confirming whether a specific account still belongs to the local Administrators group, after a privilege-escalation concern is raised?",
        options: ["Get-LocalGroupMember", "Get-Service", "Get-ChildItem", "Get-WinEvent"],
        answer: 0,
        explanation:
          "Get-LocalGroupMember -Group 'Administrators' lists exactly who currently belongs to a local group, which is the direct way to confirm or rule out unauthorized privilege after an escalation concern. Get-Service lists service states, Get-ChildItem lists files and folders, and Get-WinEvent queries the event log — none of them enumerate current group membership.",
      },
    },

    // -----------------------------------------------------------------------
    // Question 1 — pipeline object-passing, scenario framed
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "ps-soc-q1",
      question:
        "You run Get-Process | Where-Object {$_.CPU -gt 200} | Select-Object Name, Id on a workstation. A colleague who only knows batch scripting asks why you didn't need to write any text-parsing logic to pull out the CPU value before filtering on it. What is the correct technical answer?",
      options: [
        "PowerShell secretly converts the console output into a spreadsheet-like grid behind the scenes, and Where-Object filters the rows of that grid instead of parsing text",
        "Get-Process returns live process objects with real properties, including CPU; the pipe hands those objects to Where-Object directly, so it filters on the .CPU property with no string parsing at all",
        "Where-Object only works here because CPU values always print at a fixed column width, so simple position-based text parsing happens to be enough",
        "PowerShell doesn't actually filter anything in this command — it lists every process, and the {$_.CPU -gt 200} condition only changes which columns get displayed on screen",
      ],
      answer: 1,
      explanation:
        "PowerShell's Get- cmdlets return structured objects with real, named properties — CPU is a property on the object Get-Process emits, not a formatted text column. The pipe passes those objects intact to Where-Object, which reads the .CPU property directly, which is exactly why no string-parsing logic was needed. There is no hidden 'grid' conversion, no reliance on fixed-width text formatting, and the command genuinely filters the object set — it does not merely change what is displayed.",
      xp: 25,
    },

    // -----------------------------------------------------------------------
    // Question 2 — cmdlet selection, privilege check scenario
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "ps-soc-q2",
      question:
        "A helpdesk ticket says a contractor's account may still have local admin rights on a shared workstation after their engagement ended. Which single cmdlet lets you check, directly on that workstation, exactly which accounts currently belong to the local Administrators group?",
      options: [
        "Get-LocalGroupMember -Group \"Administrators\"",
        "Get-Service -Name \"Administrators\"",
        "Get-Process -Name \"Administrators\"",
        "Get-ScheduledTask -TaskPath \"\\Administrators\\\"",
      ],
      answer: 0,
      explanation:
        "Get-LocalGroupMember -Group \"Administrators\" enumerates the exact members of the local Administrators group right now — the direct answer to 'who has admin rights on this box.' Get-Service lists Windows services, not group membership; there is no service literally named Administrators. Get-Process lists running processes, unrelated to group membership entirely. Get-ScheduledTask -TaskPath targets a folder of scheduled tasks, not a security group, and \\Administrators\\ is not a real task folder.",
      xp: 25,
    },

    // -----------------------------------------------------------------------
    // Question 3 — Get-NetTCPConnection scenario
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "ps-soc-q3",
      question:
        "EDR flags a workstation for an established outbound connection to an unfamiliar external IP on port 4444, but the alert doesn't name which local process owns that connection. Which cmdlet lets you look up the live TCP connection and pull the owning process ID, so you can pivot that ID into Get-Process for the executable details?",
      options: ["Get-NetTCPConnection", "Get-ChildItem", "Get-WinEvent", "Get-Service"],
      answer: 0,
      explanation:
        "Get-NetTCPConnection lists live TCP connections, including an OwningProcess property that holds the PID responsible for each one — exactly what's needed to pivot from 'a suspicious connection exists' to 'here is the process ID, now look up the executable with Get-Process -Id.' Get-ChildItem lists files, Get-WinEvent queries historical log entries rather than the live connection table, and Get-Service lists service states — none of them expose a live connection's owning process.",
      xp: 25,
    },

    // -----------------------------------------------------------------------
    // Query fill — Get-NetTCPConnection investigation
    // -----------------------------------------------------------------------
    {
      type: "query_fill",
      id: "ps-soc-qf1",
      heading: "Write It Yourself: Confirm the Connection and Find Its Owning Process",
      language: "powershell",
      context:
        "The EDR alert from the previous question named the remote port as 4444 — a well-known default listener port for Metasploit's Meterpreter handler, which is exactly why it stood out to the correlation rule. Before escalating, you want to confirm the connection is still live on the workstation and pull the exact process ID holding it open. Build that query yourself: pull only connections that are actively open (not still listening, not already closing), filter down to the port named in the alert, and select the fields — including the property that ties the connection back to a process — that you'd hand to an incident lead.",
      template:
        "Get-NetTCPConnection -State {{state}} | Where-Object {$_.RemotePort -eq {{port}}} | Select-Object LocalAddress, RemoteAddress, RemotePort, {{property}}",
      blanks: [
        { id: "state", answers: ["Established"], placeholder: "the connection state that means 'actively open right now'" },
        { id: "port", answers: ["4444"], placeholder: "the remote port named in the alert" },
        { id: "property", answers: ["OwningProcess"], placeholder: "the property that maps a connection to a PID" },
      ],
      explanation:
        "-State Established scopes the query to connections that are actively open — not Listen (a port waiting for an inbound connection) and not TimeWait (a connection already closing), either of which would give a misleading picture of what's happening right now. RemotePort -eq 4444 filters to the exact port the alert named. OwningProcess is the property Get-NetTCPConnection carries specifically to answer 'which process holds this open' — feed that PID into Get-Process -Id to get the executable name, path, and hash for the incident ticket. This is the same filter-then-select pipeline shape from the earlier reading, just aimed at connections instead of processes.",
      xp: 30,
    },

    // -----------------------------------------------------------------------
    // Log analysis — scheduled task persistence, found via Get-ScheduledTask
    // -----------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "ps-soc-la1",
      heading: "A Scheduled Task Nobody on the IT Team Recognizes",
      context:
        "During a broader persistence sweep on a finance workstation (CORP-FIN-014) — unrelated to any single alert, just a routine check after a wave of phishing attempts across the finance department — an analyst runs Get-ScheduledTask across the box and finds one task that does not match anything the IT asset-management team has on file. Pulling the matching Windows Security event (Event ID 4698, a scheduled task was created) turns up the record below.",
      event: scheduledTaskEvent,
      questions: [
        {
          question:
            "Independent of the folder the task sits in, which combination of details in this record is the strongest reason to flag it for follow-up?",
          options: [
            "The task runs a hidden-window PowerShell command that reads a script out of the world-writable C:\\Users\\Public folder, was authored by a standard user account rather than an admin or SYSTEM, and is triggered at 23:47 — outside business hours",
            "The TaskName folder path contains the word Windows, which is reserved for Microsoft-signed tasks only and can never legitimately appear in a task created by a regular account",
            "Event ID 4698 by itself always indicates a malicious scheduled task, since legitimate administrators only use Group Policy to deploy scheduled tasks, never the Task Scheduler API directly",
            "The Command value is powershell.exe, and any scheduled task that launches powershell.exe should automatically be treated as malware regardless of anything else in the record",
          ],
          answer: 0,
          explanation:
            "No single field here proves anything on its own — this room's first reading made that point directly. It's the combination that matters: a Hidden window flag on the PowerShell command, a script sourced from a folder any user can write to, a standard user's SID (not an admin or SYSTEM) as the task author, and a trigger time well outside business hours. The folder name containing 'Windows' is meaningless on its own — plenty of legitimate third-party tasks sit under lookalike paths, and nothing enforces that naming convention. Event ID 4698 is generated by every scheduled task ever created, legitimate or not — it is not itself a verdict. And PowerShell appearing as the Command is exactly the dual-use point from Reading 1: the presence of powershell.exe proves nothing by itself.",
          xp: 25,
        },
        {
          question:
            "Which cmdlet would the analyst have used directly on CORP-FIN-014 to discover this task's existence and pull its actions locally, before ever pulling the matching Security log event?",
          options: ["Get-ScheduledTask", "Get-Process", "Get-LocalGroupMember", "Get-NetTCPConnection"],
          answer: 0,
          explanation:
            "Get-ScheduledTask is the cmdlet that enumerates scheduled tasks live on a host, including author and action — exactly what the context describes the analyst running during the persistence sweep. Get-Process lists running processes (a scheduled task that hasn't fired yet has no running process to find), Get-LocalGroupMember checks group membership, and Get-NetTCPConnection checks live network connections — none of them surface scheduled tasks.",
          xp: 25,
        },
        {
          question:
            "SubjectUserName is a standard user account, not an admin, and the task's action reads a script from C:\\Users\\Public\\upd.ps1 at the Highest Available run level. What should the analyst do next?",
          options: [
            "Retrieve and hash upd.ps1 for analysis, confirm with j.alvarez and their manager whether this task is authorized IT work, and pull EDR process-creation telemetry for powershell.exe on CORP-FIN-014 around 23:47 to see what actually ran",
            "Close the alert as expected noise, since scheduled tasks that launch PowerShell are standard on every managed Windows fleet and require no further review",
            "Delete the scheduled task immediately from the Task Scheduler console to stop it from running again, without collecting anything else first",
            "Reimage CORP-FIN-014 immediately without further investigation, since a task requesting Highest Available run level is, on its own, confirmation of compromise",
          ],
          answer: 0,
          explanation:
            "The correct next step preserves and gathers evidence before drawing a conclusion: pull the referenced script and hash it, verify with the account owner and their manager whether this is sanctioned work, and correlate against EDR process-creation events to see what the task actually executed when it fired. Closing it as noise skips the investigation the combination of indicators clearly warrants. Deleting the task first destroys evidence — the script content and any related detections should be collected before the persistence mechanism is removed. And Highest Available run level, on its own, is a request a task can make whether or not anything malicious is involved; it is not proof by itself, only one more data point to weigh alongside everything else in the record.",
          xp: 30,
        },
      ],
    },

    // -----------------------------------------------------------------------
    // Matching — cmdlet to investigative role
    // -----------------------------------------------------------------------
    {
      type: "matching",
      id: "ps-soc-match1",
      heading: "Match Each Cmdlet to What an Analyst Actually Uses It For",
      instructions:
        "Match each defensive PowerShell cmdlet on the left to the investigative task it is genuinely used for in a SOC, on the right.",
      pairs: [
        {
          id: "pair-process",
          left: "Get-Process",
          right: "List every running process (name, PID, CPU, memory) to spot something that doesn't belong right now",
        },
        {
          id: "pair-service",
          left: "Get-Service",
          right: "Confirm a security service hasn't been disabled, or spot an unfamiliar service that has appeared",
        },
        {
          id: "pair-winevent",
          left: "Get-WinEvent",
          right: "Query the Windows Event Log directly (for example, every Event ID 4625 in the last hour) without opening Event Viewer",
        },
        {
          id: "pair-childitem",
          left: "Get-ChildItem",
          right: "List files in a directory such as %TEMP% or %APPDATA% to check for a dropped payload",
        },
        {
          id: "pair-nettcp",
          left: "Get-NetTCPConnection",
          right: "List live TCP connections and their OwningProcess, to trace a suspicious outbound connection back to a PID",
        },
        {
          id: "pair-schtask",
          left: "Get-ScheduledTask",
          right: "List scheduled tasks on the host, to find a persistence mechanism registered outside normal change control",
        },
        {
          id: "pair-localgroup",
          left: "Get-LocalGroupMember",
          right: "List members of a local group such as Administrators, to confirm who currently has that level of access",
        },
      ],
      explanation:
        "These seven cmdlets are the core defensive toolkit from Reading 3, and each answers a different investigative question: what's running (Get-Process), what's installed as a service (Get-Service), what happened historically (Get-WinEvent), what's sitting on disk (Get-ChildItem), what's connected right now (Get-NetTCPConnection), what's scheduled to run later (Get-ScheduledTask), and who has privileged access (Get-LocalGroupMember). Chained through Where-Object, Select-Object, and Export-Csv, each one turns from a raw system query into a piece of case evidence.",
      xp: 35,
    },

    // -----------------------------------------------------------------------
    // Flag
    // -----------------------------------------------------------------------
    {
      type: "flag",
      id: "ps-soc-flag1",
      prompt:
        "Enter the exact name of the property, returned by Get-NetTCPConnection, that lets you pivot directly from a live TCP connection to the process ID holding it open — the same property you filled into the query_fill exercise earlier in this room.",
      answer: "OwningProcess",
      hint: "It's a property on the connection object itself, not a separate cmdlet — check the Select-Object field list from the query you built.",
      xp: 25,
    },
  ],
};

export const roomsBatch31 = [powershellForSocRoom];
