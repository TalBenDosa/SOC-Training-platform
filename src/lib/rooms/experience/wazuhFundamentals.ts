import type { RoomExperience } from "./types";

// "Operation Open Watch" for the "wazuh-fundamentals" room.
// Script: docs/campaign/35-wazuh-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Hexley Games (fictional), not the graded tasks' linux-srv-01. Lab data
// differs from the graded tasks: the manager console asks about enrollment
// and a stale agent, never the event port (r1 checkpoint); the logtest console
// decodes an sshd failure and never asks for a level band (q1) or a rule-ID
// range (flag1); the FIM console watches sshd_config, never /etc/passwd or
// /etc/sudoers (la1); and nothing configures an automatic block (q3).
export const WAZUH_FUNDAMENTALS: RoomExperience = {
  roomId: "wazuh-fundamentals",
  codename: "Operation Open Watch",
  theme: "wazuh",
  handler: { name: "Lucía Ferrer", role: "SIEM Engineer, Hexley Games" },
  briefing: [
    "Hexley Games. 300 developers, 140 Linux build servers, and a game launch in six weeks that half the internet wants to leak.",
    "There's no budget for a commercial SIEM, so Hexley runs Wazuh: open source, agents on every box, and a manager that decides what's worth an alert.",
    "Lucía Ferrer built it. She wants an analyst who knows what happens between a log line on a build server and an alert on the dashboard.",
    "Learn the agents and the manager, decoders and rules, file integrity and configuration checks, then read a real alert the way Wazuh wrote it.",
  ],
  mission: "Check agent health on the manager, push a log line through wazuh-logtest and read what each phase extracts, chase a file-integrity alert to the setting and the user that changed it, then work a new-account alert.",
  estimate: "~35 min",
  look: { primary: "#3b82f6", secondary: "#2dd4bf", warn: "#f97316" },
  scene: "wazuhflow",
  layout: "stage",
  stations: [
    {
      id: "arch",
      label: "Agents and Manager",
      topic: "Agent, manager, indexer, dashboard · the data flow and its ports",
      tagline: "Who's reporting, and who went quiet?",
      building: "control",
      taskIds: ["wazuh-r1"],
    },
    {
      id: "rules",
      label: "Decoders and Rules",
      topic: "Decoders extract, rules judge · levels 0 to 15 · rule-ID blocks",
      tagline: "Watch a log line become an alert",
      building: "lab",
      taskIds: ["wazuh-r2", "wazuh-q1"],
    },
    {
      id: "fim",
      label: "FIM and SCA",
      topic: "File integrity, configuration assessment, active response, dashboards",
      tagline: "Who changed that file?",
      building: "vault",
      taskIds: ["wazuh-r3"],
    },
    {
      id: "alert",
      label: "The New User",
      topic: "Reading a Wazuh alert: rule, level, decoder, full_log",
      tagline: "Work a real alert",
      building: "office",
      taskIds: ["wazuh-la1", "wazuh-flag1"],
    },
    {
      id: "pipeline",
      label: "Close the Loop",
      topic: "What happens after decoding · automatic countermeasures",
      tagline: "Prove you know the whole pipe",
      building: "ticket",
      taskIds: ["wazuh-q2", "wazuh-q3"],
      boss: true,
    },
  ],
  personas: {
    "wazuh-q1": { name: "Lucía Ferrer", role: "SIEM Engineer", line: "Level 12 and level 15 at once. Which do you open first?" },
    "wazuh-la1": { name: "Lucía Ferrer", role: "SIEM Engineer", line: "A new account at 02:44 on a server that never gets new accounts. Read it." },
    "wazuh-q2": { name: "Lucía Ferrer", role: "SIEM Engineer", line: "The decoder has pulled out the fields. Then what?" },
    "wazuh-q3": { name: "Lucía Ferrer", role: "SIEM Engineer", line: "Management wants brute-force IPs blocked automatically. Which feature?" },
  },
  briefings: {
    // ── Reading 1: architecture ──
    "wazuh-r1": [
      {
        kind: "queue",
        title: "Agent Health Board",
        prompt: "Before trusting any dashboard, Lucía checks which agents are really reporting. Work the health board: which agents need a ticket?",
        console: "Wazuh · Agents · wz-manager-01",
        actions: [
          { id: "ticket", label: "Raise a ticket", tone: "escalate" },
          { id: "ok", label: "Healthy, close", tone: "close" },
        ],
        alerts: [
          { id: "b014", time: "08:00", severity: "Low", rule: "Agent status", entity: "014 · build-lnx-014",
            fields: [{ k: "status", v: "Active" }, { k: "last keep alive", v: "8 s ago" }, { k: "version", v: "v4.9.2" }],
            context: "A build server reporting normally.", answer: "ok", why: "Active, current version, keep-alives arriving." },
          { id: "art", time: "08:00", severity: "High", rule: "Agent status", entity: "022 · art-store-02",
            fields: [{ k: "status", v: "Disconnected" }, { k: "last keep alive", v: "2026-11-03 19:40:12" }, { k: "holds", v: "launch art assets" }],
            context: "The server holding the unreleased game's art has been silent since 19:40 yesterday.", answer: "ticket", why: "Silence is a finding. Anything that happened there since 19:40 is invisible, on the box leakers want most." },
          { id: "b040", time: "08:00", severity: "Medium", rule: "Agent status", entity: "040 · build-lnx-040",
            fields: [{ k: "status", v: "Never connected" }, { k: "enrolled", v: "2026-10-28" }, { k: "events received", v: "0" }],
            context: "Enrolled a week ago, has never sent a single event.", answer: "ticket", why: "Enrollment worked but events never arrived: a blind spot from day one. Usually a firewall rule or the wrong manager address." },
          { id: "cdn", time: "08:00", severity: "Low", rule: "Agent status", entity: "031 · launcher-cdn-01",
            fields: [{ k: "status", v: "Active" }, { k: "last keep alive", v: "4 s ago" }, { k: "syscheck", v: "last scan 02:00" }],
            context: "The CDN node that will ship the game.", answer: "ok", why: "Reporting and scanning. Healthy, for now." },
        ],
      },
    ],
    // ── Reading 2: decoders and rules ──
    "wazuh-r2": [
      {
        kind: "tune",
        title: "Who Gets Paged?",
        prompt: "Lucía routes alerts to the on-call phone with two dials: the lowest rule level that pages, and a stand-in for the exceptions she has already reviewed and documented: rules that fired more than a set number of times today and were confirmed benign. After decoding, the rules phase sets the level and counts repeats. Level bands: 0 ignored, 1 to 3 low informational, 4 to 6 low, 7 to 11 medium, 12 to 14 high, 15 critical. Rule ID blocks: 500 to 599 rootcheck and syscheck, 5100 to 5299 Linux system, 5300 to 5999 authentication (sshd, PAM, sudo, user changes), 31100 to 31999 web server, 100000 and up your own custom rules. Set both dials, deploy, and see who gets woken for what.",
        eventColumn: "decoded alert",
        dials: [
          { id: "level", label: "Page at rule level or above", short: "level", min: 1, max: 15, step: 1, start: 1 },
          { id: "fired", label: "Treat as reviewed noise if fired more than", short: "fired today", unit: "times", min: 1, max: 500, step: 1, start: 500, dir: "below" },
        ],
        events: [
          { id: "a1", label: "adduser decoder, level 12: new account on art-store-02", bad: true, values: { level: 12, fired: 1 } },
          { id: "a2", label: "sshd decoder, level 10: failures then a success on build-lnx-015", bad: true, values: { level: 10, fired: 3 } },
          { id: "a3", label: "syscheck, level 7: rc.local changed on launcher-cdn-01, no ticket", bad: true, values: { level: 7, fired: 1 } },
          { id: "a4", label: "audit decoder, level 9: shell spawned by the game-launcher service", bad: true, values: { level: 9, fired: 2 } },
          { id: "a5", label: "cron decoder, level 6: new job on art-store-02", bad: true, values: { level: 6, fired: 1 } },
          { id: "n1", label: "syscheck, level 7: log rotation touched /var/log files", bad: false, values: { level: 7, fired: 410 } },
          { id: "n2", label: "sshd decoder, level 5: VPN users mistyping passwords", bad: false, values: { level: 5, fired: 120 } },
          { id: "n3", label: "docker decoder, level 10: container restart loop on build-lnx-022", bad: false, values: { level: 10, fired: 85 } },
          { id: "n4", label: "sudo decoder, level 11: CI runner escalates to root", bad: false, values: { level: 11, fired: 60 } },
          { id: "n5", label: "dpkg decoder, level 8: unattended upgrade installed a package", bad: false, values: { level: 8, fired: 30 } },
          { id: "n6", label: "cron decoder, level 6: deploy script rewrote its own job", bad: false, values: { level: 6, fired: 9 } },
          { id: "n7", label: "pam decoder, level 4: a login on a build host, off the CI window", bad: false, values: { level: 4, fired: 6 } },
        ],
        goal: { catch: 5, maxFalse: 0 },
        lesson: "Level is the rule author's guess; how often the rule fires is evidence. Levels 5 and 6 with a count of 8 or less catch a new cron job and an unticketed rc.local change that a level-10 cutoff never pages, while the level 10 to 12 events that fire dozens of times are the CI runner and the restart loop. The deploy script (level 6, fired 9) shows how close a benign repeat sits to the real thing. Tune rules by their repeat rate and their rule ID, not by turning the page level up until the phone goes quiet. In production, once a noisy rule is confirmed benign, also record a documented exception scoped to that rule ID and that host or user.",
      },
    ],
    // ── Reading 3: FIM and SCA ──
    "wazuh-r3": [
      {
        kind: "spotdiff",
        title: "The Baseline Moved",
        prompt: "Syscheck on launcher-cdn-01, the server that ships the game, keeps last night's baseline beside this morning's scan. Tap the entries that mean someone changed something that matters. Some differences are just a busy server.",
        goodTitle: "Baseline scan · Nov 3 02:00",
        suspectTitle: "This morning's scan · Nov 4 02:00",
        good: [
          "/usr/sbin/sshd  root:root  0755  sha256:7c1e9a40  mtime 2026-09-12",
          "/usr/bin/sudo  root:root  4755  sha256:b204d6f1  mtime 2026-09-12",
          "/etc/ssh/sshd_config  root:root  0644  sha256:3a91c0e4  mtime 2026-09-02",
          "/etc/sudoers.d/ci-runner  root:root  0440  sha256:51de88a7  mtime 2026-10-01",
          "/etc/cron.d/cdn-purge  root:root  0644  sha256:e8827b3c  mtime 2026-10-14",
          "/opt/launcher/bin/cdn-agent  cdn:cdn  0750  sha256:c93f05d2  mtime 2026-10-30",
          "/opt/launcher/etc/origins.yml  cdn:cdn  0640  sha256:0f6a77b9  mtime 2026-10-30",
          "/etc/ld.so.preload  not present",
          "/var/log/auth.log  syslog:adm  0640  sha256:2be5d0c8  mtime 2026-11-03",
          "/usr/lib/x86_64-linux-gnu/libpam.so.0  root:root  0644  sha256:1d44be90  mtime 2026-09-12",
          "/root/.ssh/authorized_keys  root:root  0600  sha256:6b3e1a52  mtime 2026-08-19",
          "/opt/launcher/releases/current  symlink to v2.4.0",
        ],
        suspect: [
          "/usr/sbin/sshd  root:root  0755  sha256:e51f02ab  mtime 2026-11-04",
          "/usr/bin/sudo  root:root  4755  sha256:b204d6f1  mtime 2026-09-12",
          "/etc/ssh/sshd_config  root:root  0644  sha256:3a91c0e4  mtime 2026-09-02",
          "/etc/sudoers.d/ci-runner  ci-runner:ci-runner  0666  sha256:51de88a7  mtime 2026-10-01",
          "/etc/cron.d/cdn-purge  root:root  0644  sha256:e8827b3c  mtime 2026-10-14",
          "/opt/launcher/bin/cdn-agent  cdn:cdn  0750  sha256:c93f05d2  mtime 2026-10-30",
          "/opt/launcher/etc/origins.yml  cdn:cdn  0640  sha256:0f6a77b9  mtime 2026-10-30",
          "/etc/ld.so.preload  root:root  0644  sha256:90d4a7f3  mtime 2026-11-04",
          "/var/log/auth.log  syslog:adm  0640  sha256:a7710e5d  mtime 2026-11-04",
          "/usr/lib/x86_64-linux-gnu/libpam.so.0  root:root  0644  sha256:1d44be90  mtime 2026-09-12",
          "/root/.ssh/authorized_keys  root:root  0600  sha256:6b3e1a52  mtime 2026-08-19",
          "/opt/launcher/releases/current  symlink to v2.4.1",
        ],
        diffs: [
          { line: 0, why: "A new sha256 and a Nov 4 mtime on the sshd binary, with no package upgrade in the change log: a replaced binary, not an edit. Confirm against the package manager's own checksum before anything else." },
          { line: 3, why: "A sudoers drop-in that was root-owned 0440 is now owned by ci-runner and world-writable 0666. The hash is unchanged, so only the owner and mode attributes reveal it: whoever controls this file controls root." },
          { line: 7, why: "A file that was not present now exists. ld.so.preload loads a library into every dynamic program, so a new entry on a CDN node is a finding with no ticket to excuse it." },
        ],
        decoys: [
          { line: 8, why: "auth.log changes every second; its hash and mtime moving is expected. Syscheck normally ignores or rate-limits growing logs." },
          { line: 11, why: "The release symlink moved from v2.4.0 to v2.4.1: the scheduled deploy. Check the change ticket, but this is the pipeline doing its job." },
        ],
        lesson: "A file integrity baseline answers three questions per path: did the content change (hash), did the owner or mode change (attributes), did the file appear or vanish. Rank the answers by what the file controls: a system binary, a sudoers rule and a preload file outrank a log and a release link. Wazuh whodata adds who made the change; always match a hit to a change ticket before closing it. The server's CIS configuration score is a separate view of the same box: integrity says what moved, configuration assessment says what was already weak.",
      },
    ],
  },
};
