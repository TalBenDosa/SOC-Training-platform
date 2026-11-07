import type { RoomExperience } from "./types";

// "Operation Flight Recorder" for the "windows-event-logs" room.
// Script: docs/campaign/23-windows-event-logs.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Morrow Bank (fictional). Lab data differs from the graded tasks: the
// retention lab teaches a cleared log on the System channel (104) and names
// the Security channel's 1102 only in passing (q2); the logon-type sheet
// shows types 3, 4, 5, 7, 9, 10 and 11 as data, asks about 9 and 11, and never
// asks about 3 from a workstation (q1) or which type is RDP (q4); the 4688 drill is a web shell
// under w3wp.exe, not Word spawning encoded PowerShell (q3); and the spray
// trace follows 198.51.100.200 to a lateral 4648, never la1's 203.0.113.45 or
// a Domain Admins change (flag1).
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
  mission: "Check how far back a Security log really reaches, read logon types beyond the basics (including the one pass-the-hash leaves), trace account-management events to the account that made them, take apart a 4688 from a web shell, and trace a password spray from the burst to the next machine it reached.",
  estimate: "~45 min",
  look: { primary: "#38bdf8", secondary: "#facc15", warn: "#f43f5e" },
  scene: "evtxtape",
  layout: "stage",
  story: {
    intro: { title: "Ten Hours of Memory", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-intro-a1cf5bfe.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-intro-6b4a782f.jpg" },
    afterStation: {
      diary: { title: "Type 9", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch2-9900a94d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch2-369acfcb.jpg" },
      logons: { title: "A Web Server Opens a Shell", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch3-c772f084.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-ch3-8bbc44c1.jpg" },
      patterns: { title: "From Spray to the Next Host", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-finale-78605706.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/windows-event-logs/flightrecorder-finale-475986de.jpg" },
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
        kind: "codebreak",
        title: "Black Box Rules",
        prompt: "An incident on MB-FS-03 started three days ago, and Rhea's first question is whether the Security log even reaches that far. Crack the six codes that decide how much evidence a Windows host really keeps.",
        tries: 6,
        rounds: [
          { id: "mode", clue: "The Security log is capped at 20 MB by default. When the file is full, the oldest records are overwritten by new ones. What is this LogMode called?", answer: "CIRCULAR", why: "Circular is the default mode: on a busy file server a 20 MB Security log may only reach back about ten hours. Evidence can vanish without any attacker touching it." },
          { id: "forward", clue: "Three days is gone locally, so events must already be sitting elsewhere. The built-in feature that pushes events from many hosts to a collector has a three-letter name. What is it?", answer: "WEF", why: "Windows Event Forwarding (or an agent shipping to the SIEM) keeps a copy off the host. Check forwarding before you promise a timeline." },
          { id: "lock", clue: "Event ID: an account was locked out. Its Caller Computer Name field names the machine the bad attempts came from.", answer: "4740", why: "4740 is logged on the DC and points at the source of the failures. It starts the trail that 4625 failures on the source machine continue." },
          { id: "priv", clue: "Event ID: special privileges assigned to a new logon. It fires for admin-equivalent sign-ins and lists rights such as SeDebugPrivilege.", answer: "4672", why: "4672 is the marker of a privileged logon. A creator of accounts, or anything reading LSASS, should have one just before the action." },
          { id: "proc", clue: "Event ID: a new process has been created. You only get it once Audit Process Creation is switched on.", answer: "4688", why: "That audit policy alone gives you the process name. The command line stays blank until a second Group Policy setting is on as well." },
          { id: "wipe", clue: "Whoever wiped the System log on MB-FS-03 could not stop Windows writing one last entry about the wipe. What Event ID does the System channel use for it?", answer: "104", why: "System 104 means that log was cleared. The Security channel has its own version, 1102. A wrap-around never produces either one: only a person or a tool clearing the log does, so treat it as someone hiding tracks and call it in now, whatever the hour." },
        ],
        lesson: "Know the log before you trust it: its size and mode decide how far back it reaches, forwarding decides whether a copy survives, and a handful of IDs (4740 lockout, 4672 privileged logon, 4688 process creation, and the entries a cleared log leaves behind) start the trails.",
      },
    ],
    // ── Reading 2: the IDs that matter ──
    "win-evtlogs-r2": [
      {
        kind: "worksheet",
        title: "The Logon Types Nobody Reads",
        prompt: "Seven 4624 events from one morning, on MB-WS-0217 and the domain controller MB-DC-01. Read the LogonType and LogonProcessName on each.",
        caption: "Security 4624 · MB-WS-0217 and MB-DC-01 · 06:00-09:00",
        columns: ["time", "TargetUserName", "LogonType", "LogonProcessName", "note"],
        rows: [
          ["06:00:01", "svc_inventory", "4", "Advapi", "scheduled task"],
          ["06:00:03", "LOCAL SERVICE", "5", "Advapi", "service start"],
          ["07:58:44", "p.osei", "11", "User32", "laptop off the network"],
          ["08:05:12", "m.dube", "10", "User32", "interactive session from MB-ADM-01"],
          ["08:31:10", "p.osei", "7", "User32", "after lunch screen lock"],
          ["08:47:22", "p.osei", "9", "seclogo", "network identity: MORROW\\adm-t.ruiz"],
          ["08:47:23", "adm-t.ruiz", "3", "NtLmSsp", "logged on MB-DC-01, from MB-WS-0217"],
        ],
        questions: [
          { id: "cached", q: "Which logon type means Windows checked the password against cached credentials, without a domain controller?", hint: "The one at 07:58.", answer: ["11", "CachedInteractive"], why: "Type 11: CachedInteractive. Normal for laptops off the network." },
          { id: "nine", q: "Which logon type keeps the local user but uses different credentials for the network?", hint: "LogonProcessName seclogo.", answer: ["9", "NewCredentials"], why: "Type 9 (NewCredentials) is what runas /netonly makes, and also what Mimikatz's pass-the-hash leaves on the source host." },
          { id: "odd", q: "p.osei is not an admin. Whose credentials appeared on the network right after the type 9 logon?", hint: "The 08:47:23 row.", answer: ["adm-t.ruiz", "t.ruiz"], why: "A standard user's session suddenly speaking as an admin to a DC: classic pass-the-hash shape. Check whether adm-t.ruiz was ever on this machine." },
        ],
      },
      {
        kind: "deduce",
        title: "Who Created the Account?",
        prompt: "A new account, report_svc3, was created on MB-DC-01 at 02:11 (event 4720). The SubjectUserName was scrubbed from your copy. Use the logon events around it to work out which session created it.",
        nameColumn: "Account",
        columns: ["Role", "Special privileges (4672)", "Logon type", "Logon source"],
        suspects: [
          { id: "dkovacs", name: "d.kovacs", cells: ["Standard user", "None", "Interactive", "MB-WS-0311"] },
          { id: "hale", name: "adm-r.hale", cells: ["IT administrator", "SeDebug, SeBackup, SeTakeOwnership", "RemoteInteractive", "MB-ADM-01 (jump host)"] },
          { id: "backup", name: "svc_backup", cells: ["Service account", "SeBackup, SeRestore", "Batch", "MB-BKP-01"] },
          { id: "admkovacs", name: "adm-d.kovacs", cells: ["Administrator", "SeDebug, SeBackup, SeTakeOwnership", "Network", "MB-WS-0311"] },
          { id: "sql", name: "svc_sql", cells: ["Service account", "None", "Service", "MB-SQL-02"] },
          { id: "farrow", name: "j.farrow", cells: ["Standard user", "None", "Interactive", "MB-WS-0108"] },
        ],
        clues: [
          "The session that created report_svc3 logged on with a 4672 event: special privileges were assigned to it.",
          "The creating logon was a person's session, not a Batch or Service logon.",
          "A 4740 at 01:58 locked out d.kovacs, with Caller Computer Name MB-WS-0311. The creating logon came from that same computer.",
        ],
        culprit: "admkovacs",
        why: "The 4672 rules out the three accounts with no special privileges, and the Batch logon rules out svc_backup. Of the two privileged people, only adm-d.kovacs signed in from MB-WS-0311, the machine named in d.kovacs's 4740 lockout shortly before: someone guessing at the workstation owner's password, then using his admin identity. adm-r.hale is the near miss: privileged and human, but arriving from the jump host IT uses for changes.",
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
          { key: "CommandLine", value: "cmd.exe /c whoami /all & net group \"domain admins\" /domain", label: "Command line", note: "Only recorded if a second Group Policy setting is enabled. Turn it on." },
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
          {
            id: "group", source: "Group-membership events · MB-DC-02 · 02:50-03:10",
            ask: "The intruder then adds a member to Finance-Auditors, a domain-wide global group used for reporting access. Which row is that change?",
            columns: ["EventID", "Meaning", "Group scope", "Example group"],
            rows: [["4732", "Member added to a security-enabled local group", "Local to one machine or domain-local", "Backup Operators, Remote Desktop Users"], ["4728", "Member added to a security-enabled global group", "Global, domain-wide", "Finance-Auditors, HR-Payroll"], ["4720", "A user account was created", "Not a group event", "None"]],
            answer: 1,
            why: "Finance-Auditors is a global group, so adding a member is 4728. The same change to a machine-local group such as Backup Operators is 4732. 4720 creates an account and touches no group.",
            learned: "Global group member added is 4728; local group member added is 4732",
          },
        ],
      },
    ],
  },
};
