import type { RoomExperience } from "./types";

// "Operation Flight Recorder" for the "windows-event-logs" room.
// Script: docs/campaign/23-windows-event-logs.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Morrow Bank (fictional). Lab data differs from the graded tasks: the
// retention console checks log size and wrap-around, never a 1102 clear (q2);
// the logon-type sheet covers types 4, 5, 7, 9 and 11, never 3 from a
// workstation (q1) or which type is RDP (q4); the 4688 drill is a web shell
// under w3wp.exe, not Word spawning encoded PowerShell (q3); and the spray
// trace follows 198.51.100.200 to a lateral 4648, never la1's 203.0.113.45 or
// a group-membership change (flag1).
export const WINDOWS_EVENT_LOGS: RoomExperience = {
  roomId: "windows-event-logs",
  codename: "Operation Flight Recorder",
  theme: "evtx",
  handler: { name: "Rhea Kapoor", role: "DFIR Lead, Morrow Bank" },
  briefing: [
    "Morrow Bank. 2,000 Windows servers and workstations, each writing its own diary every second.",
    "When something goes wrong, Rhea Kapoor's team pulls the diaries first: who logged on, how, what ran, and whether anyone tried to tear pages out.",
    "Before you can read the story you need to know how long the diary keeps it, which entries matter, and how events chain into patterns.",
    "Open the flight recorder.",
  ],
  mission: "Check how far back a Security log really reaches, read logon types beyond the basics (including the one pass-the-hash leaves), pull account-management events with PowerShell, take apart a 4688 from a web shell, and trace a password spray from the burst to the next machine it reached.",
  estimate: "~45 min",
  look: { primary: "#38bdf8", secondary: "#facc15", warn: "#f43f5e" },
  scene: "evtxtape",
  layout: "stage",
  story: {
    intro: { title: "Ten Hours of Memory", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-intro-7931b32d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-intro-d2f211f6.jpg" },
    afterStation: {
      diary: { title: "Type 9", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch2-8583affb.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch2-2130bb73.jpg" },
      logons: { title: "A Web Server Opens a Shell", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch3-1b446d98.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch3-4b609c3b.jpg" },
      patterns: { title: "From Spray to the Next Host", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-finale-f0614cb5.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-finale-5e0e8af9.jpg" },
    },
  },
  stations: [
    {
      id: "diary",
      label: "The Black Box",
      topic: "Where Windows keeps its logs · channels · size and retention · tamper signs",
      tagline: "Find out how far back the diary really goes",
      building: "archive",
      taskIds: ["win-evtlogs-r1", "win-evtlogs-q2"],
    },
    {
      id: "logons",
      label: "Who Logged On, and How",
      topic: "4624/4625 and every logon type · account-management IDs",
      tagline: "Read the logon types most analysts skip",
      building: "control",
      taskIds: ["win-evtlogs-r2", "win-evtlogs-q1", "win-evtlogs-q4"],
    },
    {
      id: "process",
      label: "What Ran",
      topic: "4688 process creation · parent, command line and token",
      tagline: "Read a process-creation event field by field",
      building: "lab",
      taskIds: ["win-evtlogs-q3"],
    },
    {
      id: "patterns",
      label: "Patterns",
      topic: "Password spray, lateral movement and building detections from sequences",
      tagline: "Follow a spray from the burst to the next host",
      building: "ticket",
      taskIds: ["win-evtlogs-r3", "win-evtlogs-la1", "win-evtlogs-flag1"],
      boss: true,
    },
  ],
  personas: {
    "win-evtlogs-q1": { name: "Rhea Kapoor", role: "DFIR Lead", line: "A 4624 type 3 on SERVER01 from a workstation's IP. Why might that matter?" },
    "win-evtlogs-q2": { name: "Rhea Kapoor", role: "DFIR Lead", line: "Saturday, 23:47, a 1102 from a domain controller. Talk to me." },
    "win-evtlogs-q3": { name: "Rhea Kapoor", role: "DFIR Lead", line: "Word, then cmd, then encoded PowerShell in a 4688. What is it?" },
    "win-evtlogs-q4": { name: "Rhea Kapoor", role: "DFIR Lead", line: "Quick one: which logon type is Remote Desktop?" },
  },
  briefings: {
    // ── Reading 1: the black box ──
    "win-evtlogs-r1": [
      {
        kind: "terminal",
        title: "How Far Back Does It Go?",
        prompt: "An incident on MB-FS-03 started about three days ago. Before you search its Security log, check whether the log even reaches that far.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-winevent\\s+-listlog\\s+security.*", help: "Get-WinEvent -ListLog Security | Format-List LogName,MaximumSizeInBytes,FileSize,LogMode,RecordCount   size and mode",
            output: "LogName            : Security\nMaximumSizeInBytes : 20971520\nFileSize           : 20975616\nLogMode            : Circular\nRecordCount        : 48211" },
          { match: "get-winevent\\s+-logname\\s+security\\s+-oldest\\s+-maxevents\\s+1.*", help: "Get-WinEvent -LogName Security -Oldest -MaxEvents 1 | Select TimeCreated,Id   the oldest event still kept",
            output: "TimeCreated            Id\n-----------            --\n11/3/2026 9:52:14 PM 4624" },
          { match: "get-winevent\\s+-logname\\s+security\\s+-maxevents\\s+1.*", help: "Get-WinEvent -LogName Security -MaxEvents 1 | Select TimeCreated,Id          the newest event",
            output: "TimeCreated            Id\n-----------            --\n11/4/2026 7:40:02 AM 4634" },
        ],
        objectives: [
          { id: "size", task: "What is the Security log's maximum size, in MB?", hint: "Get-WinEvent -ListLog Security | Format-List LogName,MaximumSizeInBytes,FileSize,LogMode,RecordCount", answer: ["20", "20 MB", "20MB"], why: "20,971,520 bytes is the Windows default of 20 MB. The file is already full." },
          { id: "mode", task: "What happens when it's full? (the LogMode)", hint: "Same output.", answer: ["Circular", "overwrite", "overwrites"], why: "Circular: the oldest events are overwritten. No attacker needed for evidence to vanish." },
          { id: "reach", task: "When is the oldest event still in the log?", hint: "Get-WinEvent -LogName Security -Oldest -MaxEvents 1 | Select TimeCreated,Id", answer: ["11/3/2026 9:52:14 PM", "11/3/2026", "9:52 PM", "21:52", "11/3/2026 9:52 PM"], why: "Only about ten hours back on a busy file server. Three days ago is gone locally: you need the SIEM copy, which is why logs must be forwarded." },
        ],
      },
    ],
    // ── Reading 2: the IDs that matter ──
    "win-evtlogs-r2": [
      {
        kind: "worksheet",
        title: "The Logon Types Nobody Reads",
        prompt: "Six 4624 events from one morning on MB-WS-0217. Read the LogonType and LogonProcessName on each.",
        caption: "Security 4624 · MB-WS-0217 · 06:00-09:00",
        columns: ["time", "TargetUserName", "LogonType", "LogonProcessName", "note"],
        rows: [
          ["06:00:01", "svc_inventory", "4", "Advapi", "scheduled task"],
          ["06:00:03", "LOCAL SERVICE", "5", "Advapi", "service start"],
          ["07:58:44", "p.osei", "11", "User32", "laptop off the network"],
          ["08:31:10", "p.osei", "7", "User32", "after lunch screen lock"],
          ["08:47:22", "p.osei", "9", "seclogo", "network identity: MORROW\\adm-t.ruiz"],
          ["08:47:23", "adm-t.ruiz", "3", "NtLmSsp", "to MB-DC-01, from MB-WS-0217"],
        ],
        questions: [
          { id: "cached", q: "Which logon type means Windows checked the password against cached credentials, without a domain controller?", hint: "The one at 07:58.", answer: ["11", "CachedInteractive"], why: "Type 11: CachedInteractive. Normal for laptops off the network." },
          { id: "nine", q: "Which logon type keeps the local user but uses different credentials for the network?", hint: "LogonProcessName seclogo.", answer: ["9", "NewCredentials"], why: "Type 9 (NewCredentials) is what runas /netonly makes, and also what Mimikatz's pass-the-hash leaves on the source host." },
          { id: "odd", q: "p.osei is not an admin. Whose credentials appeared on the network right after the type 9 logon?", hint: "The 08:47:23 row.", answer: ["adm-t.ruiz", "t.ruiz"], why: "A standard user's session suddenly speaking as an admin to a DC: classic pass-the-hash shape. Check whether adm-t.ruiz was ever on this machine." },
        ],
      },
      {
        kind: "terminal",
        title: "Account Changes",
        prompt: "Pull the account-management events from MB-DC-01 for last night.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-winevent\\s+.*id\\s*=\\s*4720.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 3 | Format-Table TimeCreated,Message -Wrap   accounts created",
            output: "TimeCreated          Message\n-----------          -------\n11/4/2026 2:11:09 AM A user account was created. Subject: MORROW\\adm-t.ruiz  New Account: MORROW\\helpdesk_svc2" },
          { match: "get-winevent\\s+.*id\\s*=\\s*4740.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740} -MaxEvents 3 | Format-Table TimeCreated,Message -Wrap   lockouts",
            output: "TimeCreated          Message\n-----------          -------\n11/4/2026 1:58:40 AM A user account was locked out. Account: MORROW\\t.ruiz  Caller Computer Name: MB-WS-0217" },
          { match: "get-winevent\\s+.*id\\s*=\\s*4672.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672} -MaxEvents 1 | Format-List TimeCreated,Message   special privileges at logon",
            output: "TimeCreated : 11/4/2026 2:10:51 AM\nMessage     : Special privileges assigned to new logon.\n              Account Name: adm-t.ruiz\n              Privileges: SeDebugPrivilege SeBackupPrivilege SeTakeOwnershipPrivilege" },
        ],
        objectives: [
          { id: "new", task: "Which account was created at 02:11?", hint: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 3 | Format-Table TimeCreated,Message -Wrap", answer: ["helpdesk_svc2"], why: "4720: a new account, created by the admin identity that just appeared via pass-the-hash." },
          { id: "lock", task: "Which machine caused t.ruiz's lockout?", hint: "Get-WinEvent ... Id=4740", answer: ["MB-WS-0217"], why: "4740's Caller Computer Name points at the source of the bad attempts: the same workstation." },
          { id: "priv", task: "4672 means a privileged logon. Name one privilege it lists.", hint: "Get-WinEvent ... Id=4672", answer: ["SeDebugPrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege"], why: "4672 fires for admin-equivalent logons. SeDebugPrivilege is what lets a tool read LSASS memory." },
        ],
      },
    ],
    // Drill before q3: a 4688 from a web shell, field by field.
    "win-evtlogs-q3": [
      {
        kind: "anatomy",
        title: "Anatomy of a 4688",
        prompt: "Before the graded 4688, read one from Morrow's internet banking web server, field by field.",
        source: "Windows Security · Event 4688 · MB-WEB-02",
        fields: [
          { key: "TimeCreated", value: "2026-11-04T03:12:44.910Z", label: "When" },
          { key: "SubjectUserName", value: "MB-WEB-02$ (IIS APPPOOL\\OnlineBanking)", label: "Who", note: "The application pool's identity: the web app itself." },
          { key: "NewProcessName", value: "C:\\Windows\\System32\\cmd.exe", label: "What started" },
          { key: "ParentProcessName", value: "C:\\Windows\\System32\\inetsrv\\w3wp.exe", label: "Parent", note: "The IIS worker process. A web server starting a shell is the textbook web-shell sign." },
          { key: "CommandLine", value: "cmd.exe /c whoami /all & net group \"domain admins\" /domain", label: "Command line", note: "Only recorded if 'Include command line in process creation events' is enabled by policy. Turn it on." },
          { key: "TokenElevationType", value: "%%1936 (TokenElevationTypeDefault)", label: "Elevation", note: "Default: full token, no UAC split. Typical of service accounts." },
          { key: "MandatoryLabel", value: "S-1-16-12288 (High)", label: "Integrity" },
        ],
        summary: "w3wp.exe > cmd.exe > discovery commands at 03:12: someone is typing through a web shell. Now judge the graded event the same way: parent first, then command line.",
      },
    ],
    // ── Reading 3: patterns ──
    "win-evtlogs-r3": [
      {
        kind: "trace",
        title: "From Spray to the Next Host",
        prompt: "A spray alert on MB-DC-02. Follow it: who got in, and where did they go next?",
        lead: "02:30: SIEM rule 'Many failed logons, many users, one source' fired on MB-DC-02.",
        steps: [
          {
            id: "burst", source: "4625 grouped by IpAddress · MB-DC-02 · 02:20-02:40",
            ask: "Which source is spraying?",
            columns: ["IpAddress", "distinct TargetUserName", "failures", "SubStatus"],
            rows: [["10.40.9.12", "1", "3", "0xC000006A"], ["198.51.100.200", "64", "64", "0xC000006A"], ["10.40.2.18", "2", "2", "0xC0000064"]],
            answer: 1,
            why: "One failure each for 64 different accounts: a spray, not a brute force. 0xC000006A means the usernames are real.",
            learned: "Spray from 198.51.100.200 against 64 real accounts",
          },
          {
            id: "hit", source: "4624 from 198.51.100.200 · MB-DC-02",
            ask: "Did any account fall?",
            columns: ["time", "TargetUserName", "LogonType", "AuthenticationPackageName"],
            rows: [["02:34:51", "k.lindgren", "3", "NTLM"]],
            answer: 0,
            why: "One success after the burst: k.lindgren's password was the season-and-year guess.",
            learned: "k.lindgren logged on from the sprayer at 02:34",
          },
          {
            id: "next", source: "4648 explicit credentials · all hosts · 02:35-02:50",
            ask: "Where did k.lindgren's credentials go next?",
            columns: ["time", "host", "SubjectUserName", "TargetUserName", "TargetServerName"],
            rows: [["02:41:07", "MB-VPN-01", "k.lindgren", "k.lindgren", "MB-FS-03"], ["02:44:30", "MB-WS-0880", "j.amari", "j.amari", "MB-PRINT-01"]],
            answer: 0,
            why: "4648 records a logon with explicitly supplied credentials: k.lindgren's account reaching for the file server.",
            learned: "02:41: k.lindgren's credentials used toward MB-FS-03: lateral movement",
          },
        ],
      },
    ],
  },
};
