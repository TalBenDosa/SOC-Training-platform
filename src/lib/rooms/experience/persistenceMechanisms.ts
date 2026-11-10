import type { RoomExperience } from "./types";

// "Operation Spare Key" for the "persistence-mechanisms" room.
// Script: docs/campaign/30-persistence-mechanisms.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Wexley Biotech (fictional), not the graded tasks' Meridian. Lab data differs
// from the graded tasks: the Run-key console never shows a VPN tray entry
// (ac1); the cron hunt is Linux only and never touches schtasks or integrity
// levels (q1); the anatomy reads a 4698 task registered to a service account,
// never la1's onstart SYSTEM task (or its /ru value, f1); the Entra worksheet
// has no mailbox forwarding rule (q3); and nothing orders containment steps
// (o1) or pairs mechanisms with their log sources (m1).
export const PERSISTENCE_MECHANISMS: RoomExperience = {
  roomId: "persistence-mechanisms",
  codename: "Operation Spare Key",
  theme: "persistence",
  handler: { name: "Ines Carvalho", role: "Incident Response Lead, Wexley Biotech" },
  briefing: [
    "Wexley Biotech. Three research sites, 1,800 staff, and a vaccine trial whose data is worth more than the buildings.",
    "Last month IT wiped a phished laptop and reset the user's password. Nine days later the same attacker was back.",
    "Ines Carvalho runs incident response. She doesn't want the door closed. She wants every spare key the attacker left behind.",
    "Learn where attackers hide a way back in: Run keys, tasks, cron, services, BITS, WMI and the cloud. Then learn the order that actually evicts them.",
  ],
  mission: "Hunt Run keys and the Startup folder, find a cron job planted without root, sweep services, BITS and WMI beyond the usual places, read a task-creation event field by field, and work out what survives a password reset in the cloud.",
  estimate: "~50 min",
  look: { primary: "#34d399", secondary: "#a78bfa", warn: "#f97316" },
  scene: "facilitypersistencemechanisms",
  layout: "facility",
  story: {
    intro: { title: "Nine Days Later", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-intro-51363139.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-intro-eada6a23.jpg" },
    afterStation: {
      timers: { title: "Every Ten Minutes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-ch2-d5e97bb7.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-ch2-1d9866c7.jpg" },
      hooks: { title: "Under the Floor", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-ch3-b8332f61.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-ch3-1c68f237.jpg" },
      evict: { title: "Change the Lock Last", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-finale-8a36e8ab.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/persistence-mechanisms/sparekey-finale-d039693e.jpg" },
    },
  },
  stations: [
    {
      id: "runkeys",
      label: "Run Keys",
      topic: "HKCU and HKLM Run and RunOnce · the Startup folder · what the hive says about access",
      tagline: "Find the entry that shouldn't start at logon",
      building: "control",
      taskIds: ["persist-r1"],
    },
    {
      id: "timers",
      label: "Tasks and Cron",
      topic: "schtasks and /ru · system and user crontabs · the setgid crontab bit",
      tagline: "Find a job planted without root",
      building: "lab",
      taskIds: ["persist-r2", "persist-q1"],
    },
    {
      id: "hooks",
      label: "Hidden Hooks",
      topic: "Services and 7045 · BITS NotifyCmdLine · WMI filter, consumer and binding",
      tagline: "Look where the usual sweep doesn't",
      building: "vault",
      taskIds: ["persist-r3", "persist-r4", "persist-q2"],
    },
    {
      id: "systask",
      label: "The SYSTEM Task",
      topic: "Reading a task registration · principal, trigger and path",
      tagline: "Read a task-creation event field by field",
      building: "office",
      taskIds: ["persist-la1", "persist-f1"],
    },
    {
      id: "evict",
      label: "Close Every Door",
      topic: "Cloud accounts and OAuth consent · why persistence changes the remediation order",
      tagline: "Evict them for good",
      building: "ticket",
      taskIds: ["persist-r5", "persist-r6", "persist-q3", "persist-ac1", "persist-m1", "persist-o1"],
      boss: true,
    },
  ],
  personas: {
    "persist-q1": { name: "Ines Carvalho", role: "Incident Response Lead", line: "A SYSTEM task from a Medium-integrity process. Would that even work?" },
    "persist-q2": { name: "Ines Carvalho", role: "Incident Response Lead", line: "Someone checked four places and called the host clean. Do you agree?" },
    "persist-la1": { name: "Ines Carvalho", role: "Incident Response Lead", line: "An accounts-payable analyst just registered a boot task. Read it with me." },
    "persist-q3": { name: "Ines Carvalho", role: "Incident Response Lead", line: "Password reset in minutes, ticket closed, mail still leaking. What did we miss?" },
    "persist-ac1": { name: "Ines Carvalho", role: "Incident Response Lead", line: "A new HKLM Run value on an ops laptop. Threat or rollout?" },
  },
  briefings: {
    // ── Reading 1: Run keys and the Startup folder ──
    "persist-r1": [
      {
        kind: "spotdiff",
        title: "Autoruns Against the Gold Image",
        prompt: "WKS-LAB14 belongs to a.rahim, a lab scientist, and EDR flagged an odd process at logon. Ines gives you the gold-image export of every logon-start location. Tap what was planted; harmless drift is not a finding.",
        goodTitle: "Gold image · logon-start locations",
        suspectTitle: "WKS-LAB14 today",
        good: [
          "HKLM Run  SecurityHealth  %windir%\\system32\\SecurityHealthSystray.exe",
          "HKLM Run  LabelPrinter  \"C:\\Program Files\\Brady\\Workstation\\bwstray.exe\"",
          "HKLM Run (Wow6432Node)  (no values)",
          "HKLM RunOnce  (no values)",
          "HKCU Run  OneDrive  \"C:\\Users\\a.rahim\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
          "HKCU Run  Slack  \"C:\\Users\\a.rahim\\AppData\\Local\\slack\\slack.exe\" --startup",
          "HKCU RunOnce  (no values)",
          "Startup folder  desktop.ini  1,214 bytes  modified 2026-03-11",
          "Startup folder  PlateReader.lnk  target C:\\Program Files\\Molecular\\PlateReader\\PlateReader.exe",
          "Startup folder (All Users)  (empty)",
        ],
        suspect: [
          "HKLM Run  SecurityHealth  %windir%\\system32\\SecurityHealthSystray.exe",
          "HKLM Run  LabelPrinter  \"C:\\ProgramData\\Brady\\bwstray.exe\"",
          "HKLM Run (Wow6432Node)  (no values)",
          "HKLM RunOnce  (no values)",
          "HKCU Run  OneDrive  \"C:\\Users\\a.rahim\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
          "HKCU Run  Slack  \"C:\\Users\\a.rahim\\AppData\\Local\\slack\\slack.exe\" --startup --updated",
          "HKCU RunOnce  syncjob  cmd /c C:\\Users\\a.rahim\\AppData\\Roaming\\mlx\\pr.bat",
          "Startup folder  desktop.ini  1,214 bytes  modified 2026-11-03",
          "Startup folder  PlateReader.lnk  target C:\\Windows\\System32\\cmd.exe /c start /min C:\\Users\\a.rahim\\AppData\\Roaming\\mlx\\pr.bat",
          "Startup folder (All Users)  (empty)",
        ],
        diffs: [
          { line: 1, why: "The value name is the same but the program moved from Program Files to ProgramData. Writing HKLM needs admin rights, so someone had already escalated on this host: persistence found in HKLM means the climb happened earlier. Sysmon Event 13 (registry value set) records a write like this." },
          { line: 6, why: "A RunOnce value runs at the next logon and then deletes itself, so a sweep tomorrow finds nothing. A script in Roaming started through cmd is not how a lab tool installs. Note it is HKCU: the user's own rights were enough." },
          { line: 8, why: "The shortcut keeps its friendly name but its target changed from the instrument viewer to a command interpreter running a batch file in AppData. Always read the target of a Startup shortcut, not its name." },
        ],
        decoys: [
          { line: 5, why: "Slack's per-user installer adds start-up flags when it updates itself, and it lives in AppData\\Local as designed. The signed binary and the unchanged folder settle it." },
          { line: 7, why: "Windows rewrites desktop.ini when a profile loads, so a new modified date is routine. Only executable content in Startup matters." },
        ],
        lesson: "Persistence has many doors, and the baseline shows which one moved. Ask which hive it sits in (HKCU needs no admin, HKLM does), whether the folder is one a vendor would use, and what a shortcut really runs. Then remove every door, not just one.",
      },
    ],
    // ── Reading 2: tasks and cron ──
    "persist-r2": [
      {
        kind: "duel",
        title: "Spare Key vs Sweep",
        prompt: "lims-app-02 runs the lab sample system and a beacon fires every few minutes, yet nobody has root and no escalation alert fired. The attacker plays a persistence trick each round. Play the sweep that finds or defeats it.",
        attacker: "The returning intruder",
        moves: [
          { id: "m1", move: "Writes a job into a user crontab", detail: "The deploy account has no sudo and no extra groups, yet a line appeared in its crontab at 23:12 last night: every ten minutes it pulls a script from an outside address and runs it.", counter: "spool", hint: "Where does cron keep the jobs of ordinary users, and who can write there?", why: "The crontab program is setgid, so it runs with group crontab, which may write the per-user spool. Nothing escalated, so no escalation alert fired: only reading the spool finds it." },
          { id: "m2", move: "Registers a logon task for the user", detail: "A task under the root folder appeared on a lab laptop. It runs a script from the user's AppData at every logon, as the user, and was registered by the user's own session.", counter: "tasks", hint: "Which Windows Security event records a task being created?", why: "Event 4698 shows the task name, its trigger, its action and its principal. Read who registered it, what it runs and as whom, and compare with change records. A user can register a task that runs as themselves, but registering one for a more privileged principal such as SYSTEM needs a caller that is already elevated: a Medium-integrity attempt is denied, so a working SYSTEM task means escalation already happened." },
          { id: "m3", move: "Slips a file into the system cron folder", detail: "A new file, sysstat-check, sits in /etc/cron.d with root as owner and a plausible name. No change ticket mentions it.", counter: "cronD", hint: "Only root can write here. What explains a file nobody approved?", why: "Package files and change tickets account for legitimate entries. A root-owned job with no record means root was already reached, which turns a cleanup into a wider incident." },
          { id: "m4", move: "Resets the file's modification time", detail: "The altered crontab now shows the same date as the files beside it, so a sort by modified time no longer shows it first.", counter: "ctime", hint: "Which timestamp can the user not set freely?", why: "The modification time can be set to anything. The change time is maintained by the kernel and moves whenever the file or its metadata changes, and a hash catches content changes." },
          { id: "m5", move: "Brings the job back after you delete it", detail: "You removed the crontab line. Ten minutes later it is there again, and the file timestamp says 23:12 yesterday.", counter: "chain", hint: "Something put it back. What are you missing?", why: "A second mechanism or a running process is re-writing the job. Find what rewrites it before you clean the first one, or the clean-up only restarts the clock." },
        ],
        cards: [
          { id: "spool", name: "Sweep the cron spool", effect: "List every per-user crontab and read the ones changed recently." },
          { id: "tasks", name: "Audit task registrations", effect: "Read the task-created events for the registrar, the action and the principal." },
          { id: "cronD", name: "Match /etc/cron.d to change records", effect: "Check each system job against package files and approved tickets." },
          { id: "ctime", name: "Compare change time and hash", effect: "Read the kernel's change time and hash the file instead of trusting the date." },
          { id: "chain", name: "Hunt the re-dropper", effect: "Trace the parent process and find the second mechanism that rewrites the job." },
          { id: "pass", name: "Reset the account password", effect: "Force a new password for the account that owns the job." },
          { id: "reboot", name: "Reboot the host", effect: "Restart the server to stop whatever is running." },
        ],
        lesson: "Persistence does not depend on a password or a running process, so resets and reboots change nothing. Read the places jobs live, the records of who made them, and the timestamps the attacker cannot set, and always look for the thing that puts it back.",
      },
    ],
    // ── Readings 3-4: services, BITS and WMI ──
    "persist-r4": [
      {
        kind: "inspect",
        title: "Autoruns Sweep",
        prompt: "Sysinternals Autoruns on WKS-LAB14, Everything tab, plus the BITS and WMI checks Ines insists on. Open every entry and judge it.",
        artifact: "Autoruns · WKS-LAB14 · Everything · Verify code signatures on",
        items: [
          { id: "sechealth", text: "Logon · HKLM\\...\\Run · SecurityHealth · Microsoft Windows Publisher (Verified)", tag: "Run key", tone: "trust", note: "Windows Security's tray icon: signed by Microsoft, in System32. Expected on every box." },
          { id: "svc", text: "Services · WexTelemetry · C:\\Users\\Public\\wtel\\wtelsvc.exe · (Not Verified) · LocalSystem · Automatic", tag: "Service", tone: "warn", note: "Unsigned, in a folder every user can write, running as SYSTEM at every boot. No vendor installs a service there." },
          { id: "defrag", text: "Scheduled Tasks · \\Microsoft\\Windows\\Defrag\\ScheduledDefrag · Microsoft Corporation (Verified)", tag: "Task", tone: "trust", note: "A built-in maintenance task, signed, in its usual folder." },
          { id: "wmi", text: "WMI · SysPerfMon · CommandLineEventConsumer · powershell.exe -nop -w hidden -enc SQBFAFgA...", tag: "WMI", tone: "warn", note: "A permanent subscription that runs hidden, encoded PowerShell a few minutes after boot. Lives in root\\subscription, not in the registry. Sysmon Events 19, 20 and 21 record the filter, the consumer and the binding being created." },
          { id: "veeam", text: "Services · VeeamAgent · C:\\Program Files\\Veeam\\Agent\\Veeam.Agent.exe · Veeam Software Group GmbH (Verified)", tag: "Service", tone: "trust", note: "The backup agent IT deployed: signed, in Program Files, matches the asset list." },
          { id: "bits", text: "bitsadmin /list /allusers · ChromeUpdateCheck · TRANSFERRED · notify: C:\\ProgramData\\cupd\\cupd.exe", tag: "BITS", tone: "warn", note: "A finished 'Chrome update' job kept only so BITS runs cupd.exe. Autoruns doesn't list BITS jobs: you have to ask BITS itself. The Bits-Client/Operational log records the job creation as Event 3." },
        ],
      },
    ],
    // Drill before the graded task event: a 4698 record, field by field.
    "persist-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of Event 4698",
        prompt: "Before the graded process event: the Security log's own record of a task being registered, field by field.",
        source: "Windows Security log · Event 4698 · A scheduled task was created · LIMS-WIN-03",
        fields: [
          { key: "EventID", value: "4698", label: "What", note: "A scheduled task was created. 4702 is updated, 4699 deleted." },
          { key: "SubjectUserName", value: "it.mbeki", label: "Who registered it", note: "The account that ran the registration, not the account the task will run as." },
          { key: "TaskName", value: "\\Wexley\\InstrumentLogSync" },
          { key: "TaskContent · Triggers", value: "<CalendarTrigger> daily 02:00", label: "When", note: "BootTrigger means every startup; LogonTrigger means at sign-in." },
          { key: "TaskContent · Exec/Command", value: "C:\\Program Files\\Wexley\\LogSync\\logsync.exe", label: "What runs", note: "Program Files: where a vendor or IT tool should live." },
          { key: "TaskContent · Principal/UserId", value: "WEXLEY\\svc-logsync", label: "Runs as", note: "The principal. This, not the subject, decides the task's privileges." },
          { key: "TaskContent · Principal/RunLevel", value: "LeastPrivilege", label: "Elevation", note: "HighestAvailable asks for the full token." },
          { key: "Change record", value: "CHG-2290 · instrument log sync", label: "Paper trail" },
        ],
        summary: "Who registered it, what runs, when, and as whom. Read the graded event the same way: the command line names all four.",
      },
    ],
    // ── Reading 5: cloud persistence ──
    "persist-r5": [
      {
        kind: "worksheet",
        title: "What the Reset Didn't Touch",
        prompt: "h.lund in Clinical Ops, who also holds the User Administrator and Privileged Role Administrator roles for the clinical systems team, was phished at 10:00. The helpdesk reset the password at 11:30 and called it done. Read the Entra audit log for that morning.",
        caption: "Microsoft Entra ID · Audit logs · 2026-11-03",
        columns: ["time", "activity", "initiated by", "target", "detail"],
        rows: [
          ["10:02", "Consent to application", "h.lund", "QuickPDF Sync", "Mail.ReadWrite, Files.Read.All, offline_access"],
          ["10:09", "Add user", "h.lund", "svc-sync02", "created in Clinical Ops"],
          ["10:11", "Add member to role", "h.lund", "svc-sync02", "Global Reader"],
          ["11:30", "Reset user password", "helpdesk.k.ito", "h.lund", "self-service disabled, temp password issued"],
          ["11:31", "Update user", "helpdesk.k.ito", "h.lund", "force change at next sign-in"],
        ],
        questions: [
          { id: "app", q: "Which app was granted access?", hint: "The consent row.", answer: ["quickpdf sync", "quickpdf"], why: "A PDF tool asking for read-write mail and every file: far more than it needs." },
          { id: "token", q: "Which permission lets the app keep working without h.lund signing in again?", hint: "One scope is about refresh tokens.", answer: ["offline_access"], why: "offline_access issues a refresh token. The reset at 11:30 changed the password, not the token." },
          { id: "acct", q: "Which account did the attacker create for later?", hint: "The 'Add user' row.", answer: ["svc-sync02"], why: "A new account with its own password and a directory role. Resetting h.lund's password doesn't touch it." },
        ],
      },
    ],
    // ── Reading 6: why the order matters ──
    "persist-r6": [
      {
        kind: "sort",
        title: "Survives the Reset?",
        prompt: "The attacker's footholds across this operation. Which ones keep working after the victim's password is reset?",
        buckets: [
          { id: "survives", label: "Still works after the reset" },
          { id: "dies", label: "Stops at the reset or the next reboot" },
        ],
        items: [
          { id: "run", text: "AdobeSyncHelper in HKCU Run on WKS-LAB14", bucket: "survives", why: "It runs a program at logon. It never asks for a password." },
          { id: "cron", text: "The deploy crontab on lims-app-02", bucket: "survives", why: "cron runs it every ten minutes as deploy, whatever anyone's password is." },
          { id: "consent", text: "QuickPDF Sync's consent with offline_access", bucket: "survives", why: "The refresh token was issued at consent time. Revoke the grant to stop it." },
          { id: "acct", text: "The svc-sync02 account", bucket: "survives", why: "Its own credentials, its own role." },
          { id: "mem", text: "A beacon living only in memory of a browser process, nothing written to disk", bucket: "dies", why: "No mechanism brings it back: it ends when the process or the host restarts." },
          { id: "sess", text: "An interactive web session that re-prompts for the password after the reset", bucket: "dies", why: "It depends on the password, so the reset ends it." },
        ],
      },
    ],
  },
};
