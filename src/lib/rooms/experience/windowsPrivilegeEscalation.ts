import type { RoomExperience } from "./types";

// "Operation Quiet Climb" for the "windows-privilege-escalation" room.
// Script: docs/campaign/32-windows-privilege-escalation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Ardent Rail (fictional), not the graded tasks' Meridian. Lab data differs
// from the graded tasks: the LSASS sort uses Sysmon 10 grants, never a failed
// 4656 request (q1); the hijack console is the eventvwr/mscfile variant read
// with reg query, never fodhelper, ms-settings or a Sysmon event ID (la1, f1,
// o1); the app-pool console shows a different site than q2's; the unquoted
// path console is a Rail Apps service, never Meridian Sync (q3); the jump
// sheet never contains ac1's installer; and nothing writes KQL (qf1) or pairs
// techniques with their signatures (m1).
export const WINDOWS_PRIVILEGE_ESCALATION: RoomExperience = {
  roomId: "windows-privilege-escalation",
  codename: "Operation Quiet Climb",
  theme: "privesc",
  handler: { name: "Priya Natarajan", role: "Threat Hunter, Ardent Rail" },
  briefing: [
    "Ardent Rail. 140 stations, a signalling network that must never stop, and 6,000 Windows endpoints from ticket machines to dispatch desks.",
    "A phishing foothold on a dispatch desk is a nuisance. The same foothold at High integrity, or as SYSTEM, can reach every credential on the box.",
    "Priya Natarajan hunts for the climb in between: the quiet step from Medium to High, and from a service account to SYSTEM.",
    "Learn to read integrity levels, LSASS access, UAC bypasses, impersonation and service misconfigurations, and to tell an approved elevation from a stolen one.",
  ],
  mission: "Read a process list by integrity level, sort LSASS access by who asked and for what, find a hijacked auto-elevate handler, check what an app-pool identity can impersonate, find an unquoted service path and a writable folder, and judge three Medium-to-High jumps.",
  estimate: "~55 min",
  look: { primary: "#f472b6", secondary: "#60a5fa", warn: "#f59e0b" },
  scene: "integrityladder",
  layout: "stage",
  stations: [
    {
      id: "levels",
      label: "Integrity Levels",
      topic: "Low, Medium, High, System · admin is not the same as elevated",
      tagline: "Read the column nobody looks at",
      building: "control",
      taskIds: ["privesc-r1"],
    },
    {
      id: "lsass",
      label: "Reaching LSASS",
      topic: "SeDebugPrivilege · access masks · LSA Protection and Credential Guard",
      tagline: "Who opened LSASS, and how far?",
      building: "vault",
      taskIds: ["privesc-r2", "privesc-q1"],
    },
    {
      id: "uac",
      label: "UAC Bypass",
      topic: "Auto-elevate binaries · the HKCU handler hijack",
      tagline: "Find the handler someone rewrote",
      building: "lab",
      taskIds: ["privesc-r3", "privesc-la1", "privesc-f1"],
    },
    {
      id: "system",
      label: "Road to SYSTEM",
      topic: "SeImpersonatePrivilege and Potatoes · unquoted paths · weak service ACLs",
      tagline: "From a service account to SYSTEM",
      building: "office",
      taskIds: ["privesc-r4", "privesc-q2", "privesc-r5", "privesc-q3"],
    },
    {
      id: "jump",
      label: "Read the Jump",
      topic: "Consent, auto-elevation or something else · hunting it fleet-wide",
      tagline: "Approved elevation or stolen one?",
      building: "ticket",
      taskIds: ["privesc-ac1", "privesc-m1", "privesc-o1", "privesc-qf1"],
      boss: true,
    },
  ],
  personas: {
    "privesc-q1": { name: "Priya Natarajan", role: "Threat Hunter", line: "A Medium process asked LSASS for everything and got refused. What does that tell you?" },
    "privesc-la1": { name: "Priya Natarajan", role: "Threat Hunter", line: "fodhelper parenting a High shell, and no consent prompt. Walk me through it." },
    "privesc-q2": { name: "Priya Natarajan", role: "Threat Hunter", line: "A web shell as an app-pool identity. How far is the attacker from SYSTEM?" },
    "privesc-q3": { name: "Priya Natarajan", role: "Threat Hunter", line: "A new Meridian.exe in Program Files, and an unquoted service path. Coincidence?" },
    "privesc-ac1": { name: "Priya Natarajan", role: "Threat Hunter", line: "Medium to High on a finance laptop. Stolen or approved?" },
  },
  briefings: {
    // ── Reading 1: integrity levels ──
    "privesc-r1": [
      {
        kind: "worksheet",
        title: "Read the Column",
        prompt: "Process Explorer on DISP-DESK-11, a dispatch desk. The user, m.osei, is in the local Administrators group with UAC on. Add the Integrity column and read it.",
        caption: "Process Explorer · DISP-DESK-11 · user m.osei",
        columns: ["process", "PID", "parent", "user", "integrity"],
        rows: [
          ["msedge.exe (renderer)", "8812", "msedge.exe", "ARDENT\\m.osei", "Low"],
          ["explorer.exe", "4120", "userinit.exe", "ARDENT\\m.osei", "Medium"],
          ["DispatchBoard.exe", "6044", "explorer.exe", "ARDENT\\m.osei", "Medium"],
          ["mmc.exe (Event Viewer)", "7310", "explorer.exe", "ARDENT\\m.osei", "High"],
          ["svchost.exe -k netsvcs", "1288", "services.exe", "NT AUTHORITY\\SYSTEM", "System"],
        ],
        questions: [
          { id: "low", q: "Which process is sandboxed at Low?", hint: "The most restricted row.", answer: ["msedge.exe", "msedge", "renderer", "the renderer", "msedge renderer"], why: "A browser renderer: even if a web page owns it, it can write almost nowhere." },
          { id: "dispatch", q: "m.osei is an admin. Why is DispatchBoard.exe still Medium?", hint: "UAC's Admin Approval Mode.", answer: ["uac", "admin approval mode", "not elevated", "it was not elevated", "it wasn't elevated", "no elevation"], why: "Admin membership gives the ability to elevate, not elevation. Everyday apps stay Medium until something asks." },
          { id: "high", q: "Which of m.osei's processes runs at High?", hint: "Find the one that went through elevation.", answer: ["mmc.exe", "mmc", "event viewer"], why: "Event Viewer is one of the binaries that auto-elevates for admins. Remember it: it comes back in the UAC station." },
        ],
      },
    ],
    // ── Reading 2: LSASS ──
    "privesc-r2": [
      {
        kind: "sort",
        title: "Who Opened LSASS?",
        prompt: "Sysmon Event 10 on DISP-DESK-11 and two neighbours: every handle granted to lsass.exe in the last day. Tune on who asked, not just the mask.",
        buckets: [
          { id: "expected", label: "Expected: tune it out" },
          { id: "hunt", label: "Hunt it" },
        ],
        items: [
          { id: "defender", text: "MsMpEng.exe (Microsoft-signed, Program Files\\Windows Defender) · GrantedAccess 0x1410", bucket: "expected", why: "Defender scans LSASS routinely. Signed, expected path, expected mask." },
          { id: "procdump", text: "procdump64.exe from C:\\Users\\m.osei\\Downloads · GrantedAccess 0x1FFFFF", bucket: "hunt", why: "A dumping tool from a Downloads folder asking for everything. Full access was granted, so it was already elevated." },
          { id: "rundll", text: "rundll32.exe with comsvcs.dll, MiniDump in the command line · GrantedAccess 0x1410", bucket: "hunt", why: "A living-off-the-land dump. The mask looks modest; the command line gives it away." },
          { id: "edr", text: "CSFalconService.exe (CrowdStrike-signed) · GrantedAccess 0x1010", bucket: "expected", why: "The EDR sensor itself. Signed, known path." },
          { id: "unknown", text: "svc_health.exe, unsigned, from C:\\ProgramData\\Ardent · GrantedAccess 0x1010", bucket: "hunt", why: "0x1010 is enough to read credentials, and it's the mask Mimikatz-style tools use. Unsigned and unexplained: hunt it." },
        ],
      },
    ],
    // ── Reading 3: UAC bypass ──
    "privesc-r3": [
      {
        kind: "terminal",
        title: "The Rewritten Handler",
        prompt: "On DISP-DESK-11 a High-integrity cmd.exe appeared under mmc.exe with no consent prompt. Event Viewer auto-elevates, and opens .msc files through a handler. Check that handler in the user's own hive.",
        shell: "cmd",
        host: "C:\\> ",
        commands: [
          { match: "reg\\s+query\\s+\"?hkcu\\\\software\\\\classes\\\\mscfile\\\\shell\\\\open\\\\command\"?.*", help: "reg query HKCU\\Software\\Classes\\mscfile\\shell\\open\\command   the per-user .msc handler",
            output: "HKEY_CURRENT_USER\\Software\\Classes\\mscfile\\shell\\open\\command\n    (Default)    REG_SZ    C:\\Users\\Public\\Libraries\\lib.cmd" },
          { match: "reg\\s+query\\s+\"?hklm\\\\software\\\\classes\\\\mscfile\\\\shell\\\\open\\\\command\"?.*", help: "reg query HKLM\\Software\\Classes\\mscfile\\shell\\open\\command   the machine-wide handler",
            output: "HKEY_LOCAL_MACHINE\\Software\\Classes\\mscfile\\shell\\open\\command\n    (Default)    REG_EXPAND_SZ    %SystemRoot%\\system32\\mmc.exe \"%1\" %*" },
          { match: "type\\s+.*lib\\.cmd.*", help: "type C:\\Users\\Public\\Libraries\\lib.cmd   what the planted handler runs",
            output: "@echo off\nstart /b cmd.exe /c \"whoami /groups > C:\\Users\\Public\\Libraries\\g.txt\"\nstart /b C:\\Users\\Public\\Libraries\\up.exe" },
          { match: "whoami\\s+/groups.*|type\\s+.*g\\.txt.*", help: "type C:\\Users\\Public\\Libraries\\g.txt   what the planted command recorded",
            output: "GROUP INFORMATION\n-----------------\n...\nBUILTIN\\Administrators          Alias  S-1-5-32-544  Enabled group, Group owner\nMandatory Label\\High Mandatory Level  Label  S-1-16-12288" },
        ],
        objectives: [
          { id: "hive", task: "Which hive holds the rewritten handler? (HKCU or HKLM)", hint: "Query both and compare.", answer: ["hkcu"], why: "Windows checks the user's own HKCU class first. Writing there needs no elevation at all." },
          { id: "payload", task: "Which program does the planted script start last?", hint: "type the .cmd file", answer: ["up.exe", "c:\\users\\public\\libraries\\up.exe"], why: "A payload in Public\\Libraries, started by a script Event Viewer ran for the attacker." },
          { id: "level", task: "At what integrity level did the planted command run?", hint: "Read the Mandatory Label line it saved.", answer: ["high", "high mandatory level"], why: "High, with no prompt: the auto-elevate binary handed its token to the hijacked handler." },
        ],
      },
    ],
    // ── Reading 4: impersonation ──
    "privesc-r4": [
      {
        kind: "terminal",
        title: "What Can the App Pool Do?",
        prompt: "A web shell on WEB-TIX-02, the ticketing portal. You're looking through its eyes. Check who it is and what it may do.",
        shell: "cmd",
        host: "c:\\windows\\system32\\inetsrv> ",
        commands: [
          { match: "^whoami\\s*$", help: "whoami",
            output: "iis apppool\\ticketportal" },
          { match: "whoami\\s+/priv.*", help: "whoami /priv",
            output: "PRIVILEGES INFORMATION\n----------------------\n\nPrivilege Name                Description                               State\n============================= ========================================= ========\nSeAssignPrimaryTokenPrivilege Replace a process level token             Disabled\nSeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled\nSeAuditPrivilege              Generate security audits                  Disabled\nSeChangeNotifyPrivilege       Bypass traverse checking                  Enabled\nSeImpersonatePrivilege        Impersonate a client after authentication Enabled\nSeCreateGlobalPrivilege       Create global objects                     Enabled\nSeIncreaseWorkingSetPrivilege Increase a process working set            Disabled" },
          { match: "(sc|sc\\.exe)\\s+query\\s+spooler.*", help: "sc query spooler   is the print spooler running here?",
            output: "SERVICE_NAME: spooler\n        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)\n        STATE              : 4  RUNNING" },
        ],
        objectives: [
          { id: "who", task: "Which account is the web shell running as?", hint: "whoami", answer: ["iis apppool\\ticketportal", "ticketportal"], why: "A virtual app-pool account: low-privileged on purpose." },
          { id: "priv", task: "Which enabled privilege makes a Potato attack possible?", hint: "whoami /priv: look at the State column", answer: ["seimpersonateprivilege", "seimpersonate"], why: "It exists so the app pool can act as connecting users. A coerced SYSTEM connection is just another user to impersonate." },
          { id: "spool", task: "Is the print spooler running? (yes/no)", hint: "sc query spooler", answer: ["yes", "running"], why: "A running spooler on a web server is one of the coercion paths PrintSpoofer-style tools use. Ask why it's on." },
        ],
      },
    ],
    // ── Reading 5: unquoted paths and weak ACLs ──
    "privesc-r5": [
      {
        kind: "terminal",
        title: "The Path With Spaces",
        prompt: "SIG-MON-04 monitors trackside signals. Find any SYSTEM service with an unquoted path, then check who can write where Windows will look first.",
        shell: "cmd",
        host: "C:\\> ",
        commands: [
          { match: "wmic\\s+service\\s+get\\s+.*pathname.*", help: "wmic service get name,pathname,startname | findstr /i /v \"C:\\Windows\\\\\"   non-Windows services",
            output: "Name             PathName                                              StartName\nArdentTelemetry  \"C:\\Program Files\\Ardent\\Telemetry\\atel.exe\"         LocalSystem\nSigMonAgent      C:\\Rail Apps\\Signal Monitor\\bin\\sigmon.exe          LocalSystem\nVeeamAgent       \"C:\\Program Files\\Veeam\\Agent\\Veeam.Agent.exe\"     LocalSystem" },
          { match: "icacls\\s+\"?c:\\\\rail apps\\\\?\"?\\s*$", help: "icacls \"C:\\Rail Apps\"",
            output: "C:\\Rail Apps BUILTIN\\Administrators:(OI)(CI)(F)\n             NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n             BUILTIN\\Users:(OI)(CI)(RX,W)\n\nSuccessfully processed 1 files; Failed processing 0 files" },
          { match: "icacls\\s+\"?c:\\\\\"?\\s*$", help: "icacls C:\\",
            output: "C:\\ BUILTIN\\Administrators:(OI)(CI)(F)\n    NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n    BUILTIN\\Users:(OI)(CI)(RX)\n    NT AUTHORITY\\Authenticated Users:(AD)\n\nSuccessfully processed 1 files; Failed processing 0 files" },
          { match: "dir\\s+\"?c:\\\\rail apps\\\\?\"?\\s*$", help: "dir \"C:\\Rail Apps\"",
            output: " Directory of C:\\Rail Apps\n\n11/04/2026  01:12    <DIR>          Signal Monitor\n11/04/2026  01:40            73,728 Signal.exe\n               1 File(s)         73,728 bytes" },
        ],
        objectives: [
          { id: "svc", task: "Which service has an unquoted path with spaces?", hint: "The wmic query: look for a path without quotes", answer: ["sigmonagent"], why: "No quotes, two spaces, LocalSystem. Windows will try shorter paths first." },
          { id: "first", task: "Which path does Windows try first? (include .exe)", hint: "Cut at the first space, add .exe", answer: ["c:\\rail.exe"], why: "C:\\Rail.exe, then C:\\Rail Apps\\Signal.exe, then the real sigmon.exe." },
          { id: "planted", task: "dir the folder. Which candidate has someone already planted? (file name)", hint: "Users can write to C:\\Rail Apps; look inside it.", answer: ["signal.exe"], why: "C:\\Rail Apps\\Signal.exe is the second candidate, in a folder Users can write. At the next service start it runs as SYSTEM." },
        ],
      },
    ],
    // ── Boss: three jumps before the graded verdict ──
    "privesc-ac1": [
      {
        kind: "worksheet",
        title: "Three Jumps",
        prompt: "Three Medium-to-High jumps from Ardent's dispatch floor this week. For each, look for the evidence that explains it.",
        caption: "Sysmon 1 · IntegrityLevel High · parent at Medium · Ardent Rail",
        columns: ["host", "child (High)", "parent", "consent.exe in session?", "record"],
        rows: [
          ["DISP-DESK-03", "TimetableSetup.msi via msiexec.exe", "explorer.exe", "yes, 3 s earlier", "Intune app assignment ITA-778"],
          ["DISP-DESK-07", "powershell.exe -nop -w hidden", "sdclt.exe", "no", "none"],
          ["DISP-DESK-11", "mmc.exe eventvwr.msc", "explorer.exe", "no", "user opened Event Viewer from Start"],
        ],
        questions: [
          { id: "odd", q: "Which host needs an incident ticket?", hint: "No prompt, no record, and a parent that shouldn't launch shells.", answer: ["disp-desk-07"], why: "sdclt.exe is another auto-elevate binary. Launching a hidden PowerShell with no prompt and no record is the bypass pattern." },
          { id: "why11", q: "DISP-DESK-11 has no consent prompt either. Why is it fine?", hint: "Which binary is the High process?", answer: ["auto-elevate", "auto elevate", "autoelevate", "mmc auto-elevates", "event viewer auto-elevates", "it auto-elevates"], why: "mmc.exe for Event Viewer auto-elevates by design and was started by the user from explorer. What it launches next is what you'd watch." },
        ],
      },
    ],
  },
};
