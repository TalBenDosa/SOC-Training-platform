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
  title: "PowerShell for the SOC Analyst: The Defender's Side of the Same Tool",
  description:
    "You have already seen PowerShell used against you: encoded commands, execution-policy bypass, winword.exe spawning a payload downloader. This room teaches the other half: the seven cmdlets an analyst actually reaches for during an investigation, how the object pipeline chains them together, and how to turn a live query into evidence you can hand to an incident lead.",
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
        "In windows-fundamentals you learned to read PowerShell as an attacker technique: a Base64 -EncodedCommand, a hidden window, an execution-policy bypass, winword.exe spawning powershell.exe as the second step of a phishing chain. That reading was correct, and those indicators are real. But it only ever showed you one side of the tool. Every one of those attacker capabilities, running a command non-interactively, reaching out to a remote host, reading and writing files, inspecting what is running on a machine: is also, line for line, exactly what an analyst needs to investigate an incident. PowerShell is not an attacker tool that defenders occasionally borrow. It is a general-purpose administration shell that both sides use for the same underlying reason: it is the most capable way to interrogate a Windows system from the command line, and it ships on every modern Windows box by default.\n\nThis is what security engineers call a dual-use tool: a piece of software with no inherent moral direction, whose classification as 'attacker' or 'defender' depends entirely on who is running it, against what, and why, not on anything different in the binary itself. PsExec, certutil, rundll32, and even a plain web browser are dual-use in the same sense. PowerShell is simply the most powerful and most common example, because Microsoft built it to be exactly that capable on purpose, for administrators.\n\nThink about what that phishing chain from windows-fundamentals actually needed PowerShell to do: download a remote file and run it, without writing anything obviously suspicious to disk first. Now think about a real investigative task: an analyst who suspects a workstation has an unauthorized scheduled task needs to enumerate every task on that host, filter out the ones signed by Microsoft, and export the rest to a CSV for the incident ticket. Different goal, same underlying primitive: query the system, filter down to what matters, act on the result. The attacker's one-liner and the analyst's investigative pipeline are both, technically, 'just PowerShell.'\n\nSo if the tool cannot tell you who is using it, what can? Two things, and this room is built around both. First, cmdlets: PowerShell ships hundreds of built-in commands (cmdlets, pronounced 'command-lets') purpose-built for administration and investigation, Get-Process, Get-Service, Get-WinEvent, Get-ChildItem, Get-NetTCPConnection, Get-ScheduledTask, Get-LocalGroupMember. Be aware that these are dual-use too: attackers run several of the very same cmdlets for Discovery. Get-Process (T1057 Process Discovery), Get-LocalGroupMember (T1069.001 Local Groups), Get-NetTCPConnection (T1049 System Network Connections Discovery), Get-ScheduledTask, so the cmdlet name alone never tells you who is at the keyboard. Second, context: exactly as the earlier room put it, a defender's Get-WinEvent call runs interactively, from a visible console, under the analyst's own logged-in credentials, against a known log, while an attacker's PowerShell often runs hidden, spawned from an unrelated parent process, reaching out to the internet. Same binary. Opposite shape of use.\n\nThe goal of this room is narrow and practical: give you the cmdlets, the pipeline habits, and the worked examples to actually run an investigation in PowerShell, not just recognize when someone else has abused it.",
      checkpoint: {
        question:
          "Two EDR records show powershell.exe running Get-Process on the same host within an hour. Per the reading, what best separates the analyst's run from a possible attacker's?",
        options: [
          "The cmdlet itself, since Get-Process is a defensive triage cmdlet that attackers rarely need",
          "How it ran: an interactive console under the analyst's own logon, not hidden under an unrelated parent",
          "The binary: the analyst's run uses a separately signed powershell.exe kept in a protected folder",
          "The privilege level: a run under an administrator account points to IT staff rather than an attacker",
        ],
        answer: 1,
        explanation:
          "The reading's point is that PowerShell and its cmdlets are dual-use, so what separates the two runs is context: the analyst works interactively, in a visible console, under their own logon, while attacker PowerShell often runs hidden, spawned from an unrelated parent process. “The cmdlet itself” is wrong because Get-Process is exactly what attackers run for Process Discovery (T1057), so the name tells you nothing about who typed it. “A separately signed powershell.exe” does not exist: both sides run the same Microsoft binary. “An administrator account” proves little, because an attacker who has stolen or escalated to admin credentials runs under an admin account too; what matters is whose logon and what kind of session.",
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
        "A single cmdlet rarely answers an investigative question on its own. Get-Process lists every process on a box. Hundreds of rows, almost all of them irrelevant to the one you actually care about. The real power shows up when you chain cmdlets together with the pipe operator, written as a single vertical bar between commands. This is the same idea you may already know from Linux shells, where a pipe passes one command's text output into the next command as input. PowerShell's pipe does something more useful: it passes structured objects, not printed text.\n\nEvery cmdlet that starts with 'Get-' returns live objects with real, named properties. Get-Process returns process objects with a Name property, a CPU property, an Id property, and more. When you pipe that output into another cmdlet, you are handing over those objects intact, properties and all, not a block of formatted text that the next command has to re-parse with string matching or regular expressions. This is the mechanical reason PowerShell scripting feels so different from batch scripting or classic Unix shell one-liners: you filter and reshape data by property name, directly, every time.\n\nThree cmdlets do almost all of the reshaping work in a typical investigative pipeline:\n\nWhere-Object filters the objects flowing through the pipeline down to the ones matching a condition. The special variable $_ inside the filter block means 'the current object.' Where-Object {$_.CPU -gt 100} keeps only the process objects whose CPU property is greater than 100, nothing about parsing columns of text, just a direct comparison on a real property. (Note what CPU means: it is the TOTAL processor time, in seconds, the process has used since it started, not its current load, so -gt 100 means 'has burned more than 100 CPU-seconds so far'.)\n\nSelect-Object narrows the objects down to specific properties, so the result is readable instead of a wall of every property a process object happens to carry. Select-Object Name, Id, CPU keeps exactly those three fields per object and drops the rest.\n\nSort-Object reorders the objects by a property. Useful for putting the highest-CPU or most-recent items at the top of a long result set before you scroll through it.\n\nAnd at the end of an investigative pipeline, Export-Csv writes whatever objects are left to a CSV file on disk, turning a live query into a durable artifact, something you can attach to a ticket, hand to an incident lead, or open in a spreadsheet six months later during a compliance review.\n\nPut all four together and you get a complete, working investigative one-liner:\n\nGet-Process | Where-Object {$_.CPU -gt 100} | Select-Object Name, Id, CPU | Export-Csv suspicious_processes.csv -NoTypeInformation\n\nRead it left to right, the way it actually executes. Get-Process produces every running process as an object. The pipe hands those objects, unmodified, to Where-Object, which keeps only the ones whose CPU property exceeds 100. The pipe hands that smaller set to Select-Object, which trims each surviving object down to just Name, Id, and CPU. The pipe hands that trimmed set to Export-Csv, which writes it to suspicious_processes.csv. The -NoTypeInformation flag simply suppresses an extra header line PowerShell would otherwise add, which most spreadsheet tools do not expect. One line, four cmdlets, and a piece of evidence that did not exist a second before you ran it.\n\nThis chained, filter-then-select-then-export shape is not specific to processes. It is the same shape you will use to filter scheduled tasks down to the ones not authored by Microsoft, filter TCP connections down to a specific remote port, or filter event log entries down to a specific event ID and time window. Learn the shape once, and every cmdlet in the rest of this room slots into it.",
      codeExample:
        "Get-Process | Where-Object {$_.CPU -gt 100} | Select-Object Name, Id, CPU | Export-Csv suspicious_processes.csv -NoTypeInformation",
      checkpoint: {
        question:
          "In the reading's pipeline example, what does the pipe (|) between Get-Process and Where-Object actually pass along?",
        options: [
          "The text Get-Process would print to the console, which Where-Object then searches",
          "Process objects whose named properties, such as CPU, Where-Object reads directly",
          "Only the process names, joined into one comma-separated line of text",
          "A formatted table, which Where-Object splits into fixed-width columns",
        ],
        answer: 1,
        explanation:
          "PowerShell's pipe passes structured objects, not printed text: Get-Process emits process objects, and Where-Object reads a property such as CPU directly by name. “The text Get-Process would print to the console” describes a Unix-style text pipe, which is exactly the contrast the reading draws. “Only the process names, joined into one comma-separated line” would lose every other property, yet the same pipeline goes on to select Name, Id and CPU. “A formatted table split into fixed-width columns” is still text parsing; the table you see on screen is only how PowerShell displays objects at the end of the pipeline, not what travels through it.",
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
        "These seven cmdlets cover the large majority of what an analyst actually reaches for during a live endpoint investigation. None of them require third-party tooling. Every one ships with Windows.\n\nGet-Process: lists every running process, with PID, cumulative CPU time (seconds), and memory. Your first stop when a ticket says 'this machine feels slow' or 'EDR flagged a process I don't recognize.' Pipe it through Where-Object {$_.Name -eq 'powershell'} to isolate every PowerShell instance running right now, or Sort-Object CPU -Descending to see which processes have used the most processor time since they started (for load at this moment, use Get-Counter '\\Process(*)\\% Processor Time' instead).\n\nGet-Service: lists Windows services and their current state (Running, Stopped, Paused). Useful two ways: confirming a security service (like the EDR sensor or Windows Defender) is actually running and was not disabled, and spotting an unfamiliar service name that was not there during the last baseline. Get-Service | Where-Object {$_.Status -eq 'Running'} narrows a long list down to what is actually active.\n\nGet-WinEvent (and its older, slower sibling Get-EventLog): queries the Windows Event Log directly from the command line, without opening Event Viewer. This is the cmdlet you reach for constantly: pulling every failed logon (Event ID 4625) in the last hour, every process-creation event (4688), or every scheduled-task-created event (4698) tied to a specific host. Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)} filters at the source instead of pulling the entire log and searching through it afterward, which matters on a busy domain controller where the Security log can hold hundreds of thousands of entries.\n\nGet-ChildItem. PowerShell's equivalent of dir or ls: lists files and folders. Investigatively useful for checking what has been dropped into %TEMP%, %APPDATA%, or C:\\Users\\Public: the same user-writable, rarely-audited locations attackers favor for staging payloads, precisely because a standard user can write there without needing elevation. When it turns up a suspicious file, Get-FileHash followed by the file's path returns its SHA256 hash, which you record in the ticket and look up in threat intelligence before anyone changes or removes the file.\n\nGet-NetTCPConnection. Lists live TCP connections on the host, including local and remote address, remote port, connection state, and an OwningProcess property holding the PID that owns each connection. This is how you go from 'EDR flagged an outbound connection to an unfamiliar IP' to 'here is the exact process holding that connection open'. Filter by -State Established and the remote port named in the alert, then pivot the OwningProcess value straight into Get-Process -Id to see the actual executable.\n\nGet-ScheduledTask. Lists every scheduled task registered on the host, including its author and the folder path it lives under. Scheduled tasks are one of the most common persistence mechanisms, because a task set to run at logon or on a timer survives a reboot without needing a running process the whole time. Get-ScheduledTask | Where-Object {$_.Author -notlike '*Microsoft*'} is a fast first pass at separating built-in Windows tasks from everything else on the box.\n\nGet-LocalGroupMember: lists the members of a local group, most often -Group 'Administrators'. This is the cmdlet you reach for after any privilege-escalation concern: a helpdesk ticket about a former contractor, a suspicious group-membership change in a SIEM alert, or simply confirming that a workstation's local admin group matches what IT change control says it should.\n\nNone of these seven cmdlets require anything beyond what ships on a default Windows install, and every one of them slots into the pipeline pattern from the previous reading: query with the Get- cmdlet, narrow with Where-Object, trim with Select-Object, and (when the result needs to leave your session as evidence) write it out with Export-Csv.",
      checkpoint: {
        question:
          "On a busy domain controller you need every failed logon (Event ID 4625) from the last hour. Why does the reading prefer Get-WinEvent -FilterHashtable over reading the whole Security log and piping it to Where-Object?",
        options: [
          "The filter is applied at the source, so only matching events are read rather than the entire log",
          "Where-Object cannot compare event IDs, because event records reach it as formatted lines of text",
          "Where-Object has no access to when an event was logged, so only a hashtable can apply a time window",
          "The hashtable query returns extra detail, such as message text, that piped event records leave out",
        ],
        answer: 0,
        explanation:
          "The reading's reason is efficiency: -FilterHashtable with LogName, Id and StartTime filters at the source, so Windows hands back only the matching events instead of every record for Where-Object to sift through afterward, which matters when a domain controller's Security log holds hundreds of thousands of entries. “Event records reach it as formatted lines of text” repeats the text-pipe misconception from Reading 2: Get-WinEvent emits event objects, and Where-Object can compare their Id. “No access to when an event was logged” is wrong for the same reason: each event object carries its time, so a piped filter could apply a window, just far more slowly. “Extra detail, such as message text” is wrong because both routes return the same kind of event object; the difference is how many records have to be read, not what each one contains.",
      },
    },

    // -----------------------------------------------------------------------
    // Question 1 — pipeline object-passing, scenario framed
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "ps-soc-q1",
      question:
        "On a file server that has been up for 30 days, you run Get-Process | Sort-Object CPU -Descending. svchost.exe is the first row, with a CPU value of 5400, and a colleague concludes it is maxing out the processor right now. What is the correct reading of that value?",
      options: [
        "An average percentage over the last minute, so 5400 means many cores have been fully busy",
        "Total processor-seconds since the process started; check current load with Get-Counter",
        "Milliseconds of processor time in the latest sampling interval, so it confirms a spike now",
        "Not a reliable number, because Sort-Object turns CPU into text and orders it alphabetically",
      ],
      answer: 1,
      explanation:
        "Reading 2 defines CPU as the total processor time, in seconds, that a process has used since it started. 5400 seconds is 90 minutes of processor time spread over 30 days, which says nothing about the load at this moment; Reading 3 points to Get-Counter '\\Process(*)\\% Processor Time' for that. “An average percentage over the last minute” and “milliseconds in the latest sampling interval” both read a lifetime total as a current measurement, which is the misreading the reading warns against. “Sort-Object turns CPU into text” is wrong because the pipeline passes objects, so CPU stays a number and Sort-Object orders it numerically.",
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
        "Get-LocalUser -Name \"Administrator\"",
        "Get-LocalGroup -Name \"Administrators\"",
        "Get-ADGroupMember -Identity \"Administrators\"",
      ],
      answer: 0,
      explanation:
        "Get-LocalGroupMember -Group \"Administrators\" enumerates the exact members of the local Administrators group right now: the direct answer to 'who has admin rights on this box.' Get-LocalUser -Name \"Administrator\" returns the single built-in account, not who belongs to the group. Get-LocalGroup -Name \"Administrators\" returns the group object itself (name, description, SID) without listing its members. Get-ADGroupMember queries a domain group in Active Directory, not the workstation's own local group.",
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
      options: ["Get-NetTCPConnection", "Get-NetIPAddress", "Get-NetFirewallRule", "Get-DnsClientCache"],
      answer: 0,
      explanation:
        "Get-NetTCPConnection lists live TCP connections, including an OwningProcess property that holds the PID responsible for each one: exactly what's needed to pivot from 'a suspicious connection exists' to 'here is the process ID, now look up the executable with Get-Process -Id.' Get-NetIPAddress shows the host's own interface addresses, Get-NetFirewallRule lists firewall policy rather than live sessions, and Get-DnsClientCache shows recently resolved names. None of them expose a live connection's owning process.",
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
        "The EDR alert from the previous question named the remote port as 4444: a well-known default listener port for Metasploit's Meterpreter handler, which is exactly why it stood out to the correlation rule. Before escalating, you want to confirm the connection is still live on the workstation and pull the exact process ID holding it open. Build that query yourself: pull only connections that are actively open (not still listening, not already closing), filter down to the port named in the alert, and select the fields (including the property that ties the connection back to a process) that you'd hand to an incident lead.",
      template:
        "Get-NetTCPConnection -State {{state}} | Where-Object {$_.RemotePort -eq {{port}}} | Select-Object LocalAddress, RemoteAddress, RemotePort, {{property}}",
      blanks: [
        { id: "state", answers: ["Established", "'Established'", '"Established"'], placeholder: "the connection state that means 'actively open right now'" },
        { id: "port", answers: ["4444", "'4444'", '"4444"'], placeholder: "the remote port named in the alert" },
        { id: "property", answers: ["OwningProcess", "'OwningProcess'", '"OwningProcess"'], placeholder: "the property that maps a connection to a PID" },
      ],
      explanation:
        "-State Established scopes the query to connections that are actively open, not Listen (a port waiting for an inbound connection) and not TimeWait (a connection already closing), either of which would give a misleading picture of what's happening right now. RemotePort -eq 4444 filters to the exact port the alert named. OwningProcess is the property Get-NetTCPConnection carries specifically to answer 'which process holds this open'. Feed that PID into Get-Process -Id to get the executable's name and path, then hash that file with Get-FileHash for the incident ticket. This is the same filter-then-select pipeline shape from the earlier reading, just aimed at connections instead of processes.",
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
        "During a broader persistence sweep on a finance workstation (CORP-FIN-014). Unrelated to any single alert, just a routine check after a wave of phishing attempts across the finance department: an analyst runs Get-ScheduledTask across the box and finds one task that does not match anything the IT asset-management team has on file. Pulling the matching Windows Security event (Event ID 4698, a scheduled task was created) turns up the record below.",
      event: scheduledTaskEvent,
      questions: [
        {
          question:
            "Which interpretation of this record best justifies flagging the task for follow-up?",
          options: [
            "Several details together: hidden PowerShell running a script from C:\\Users\\Public, a standard-user author, a 23:47 trigger",
            "Event 4698 itself, because Windows writes it only for tasks created outside Group Policy or Intune deployments",
            "The HighestAvailable run level, because it makes the task run with SYSTEM rights whoever registered it",
            "Nothing yet: a WindowsUpdate folder plus HighestAvailable is how endpoint-management tools deploy maintenance tasks",
          ],
          answer: 0,
          explanation:
            "No single field proves anything here; the combination does. The action starts PowerShell with a hidden window, it runs a script from C:\\Users\\Public (a folder any user can write to), the author is a standard user's SID rather than SYSTEM or an admin, and the trigger is 23:47. The WindowsUpdate folder adds weight as a supporting indicator: a user-authored task filed under \\Microsoft\\Windows\\ is a known masquerading pattern (T1036.004), though the folder alone proves nothing. “Windows writes it only for tasks created outside Group Policy or Intune” is wrong: 4698 is logged for every task registration, legitimate or not, so it is not a verdict. “SYSTEM rights whoever registered it” misreads HighestAvailable: it requests the highest privileges available to the task's own principal, which for a standard user is still a standard token. “How endpoint-management tools deploy maintenance tasks” is the competing benign story, but management tools register tasks as SYSTEM or a service account, not under an individual user's SID, and they do not run scripts out of a public folder.",
          xp: 25,
        },
        {
          question:
            "The analyst's first pass in the sweep was the reading's filter Get-ScheduledTask | Where-Object {$_.Author -notlike '*Microsoft*'}. Judging by this record, does this task survive that filter, and why?",
          options: [
            "Kept: the filter tests Author, and CORP\\j.alvarez does not match *Microsoft*",
            "Dropped: its path sits under \\Microsoft\\Windows\\, so the filter treats it as built in",
            "Dropped: its action runs powershell.exe from System32, a Microsoft-signed binary",
            "Kept, but only because its 23:47 trigger falls outside business hours",
          ],
          answer: 0,
          explanation:
            "Where-Object {$_.Author -notlike '*Microsoft*'} tests one property, Author, and the task definition shows the author as CORP\\j.alvarez, which does not contain “Microsoft”, so the task stays in the result. “Its path sits under \\Microsoft\\Windows\\” confuses the folder the task is filed in with its author: filing a task in a Microsoft folder does not change who registered it, which is why an Author-based first pass still catches this masquerade while a filter on the folder path alone would have hidden it. “Runs powershell.exe from System32” confuses the action's binary with the author; the filter never looks at the action. “Only because its 23:47 trigger” is wrong because the filter does not test the trigger at all; the time is a separate indicator you weigh afterward.",
          xp: 25,
        },
        {
          question:
            "You have flagged this task for follow-up, and nothing on CORP-FIN-014 has been changed yet. What should the analyst do next?",
          options: [
            "Collect and hash the script it loads, ask j.alvarez's manager if the task is sanctioned, and review process events near 23:47",
            "Unregister the task right away so it cannot fire again, then look for the script and any process activity it caused",
            "Disable j.alvarez's account and reimage CORP-FIN-014, since a user-made task at HighestAvailable confirms compromise",
            "Message j.alvarez to ask whether they created the task, and close the case as sanctioned if they say they did",
          ],
          answer: 0,
          explanation:
            "Evidence comes before conclusions and before cleanup: collect the script the task points to and record its hash (Get-FileHash, Reading 3), verify through j.alvarez's manager whether this is sanctioned IT work, and pull process-creation telemetry for powershell.exe around 23:47 to see whether the task already ran and what it did. “Unregister the task right away” is the right containment step at the wrong time: removing the persistence before collecting the script and checking what already ran risks losing the evidence of what the task did; collect first, then remove it. “Disable the account and reimage” jumps to eradication on indicators that still need confirming, and wipes the host evidence that would show scope. “Message j.alvarez to ask whether they created the task” trusts the very account that registered it; if that account is compromised, the attacker may be the one answering, and a yes still would not explain a hidden script in a public folder.",
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
        "Before the scheduled task on CORP-FIN-014 is removed, you want to collect the script it loads and hash it. Enter the file name of that script (name and extension only, no folder path).",
      answer: "upd.ps1",
      hint: "The 4698 record carries the full task definition, not just the program it starts.",
      xp: 25,
    },
  ],
};

export const roomsBatch31 = [powershellForSocRoom];
