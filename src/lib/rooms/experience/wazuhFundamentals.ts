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
        kind: "terminal",
        title: "Through the Logtest",
        prompt: "wazuh-logtest shows exactly what the manager does with one log line. Feed it a failed SSH login from build-lnx-015.",
        shell: "bash",
        host: "lucia@wz-manager-01:~$ ",
        commands: [
          { match: "(sudo\\s+)?(/var/ossec/bin/)?wazuh-logtest.*", help: "sudo /var/ossec/bin/wazuh-logtest   then the line is fed for you",
            output: "Starting wazuh-logtest v4.9.2\nType one log per line\n\nNov  4 01:12:44 build-lnx-015 sshd[40211]: Failed password for root from 198.51.100.77 port 50644 ssh2\n\n**Phase 1: Completed pre-decoding.\n\tfull event: 'Nov  4 01:12:44 build-lnx-015 sshd[40211]: Failed password for root from 198.51.100.77 port 50644 ssh2'\n\ttimestamp: 'Nov  4 01:12:44'\n\thostname: 'build-lnx-015'\n\tprogram_name: 'sshd'\n\n**Phase 2: Completed decoding.\n\tname: 'sshd'\n\tparent: 'sshd'\n\tdstuser: 'root'\n\tsrcip: '198.51.100.77'\n\tsrcport: '50644'\n\n**Phase 3: Completed filtering (rules).\n\tid: '5760'\n\tlevel: '5'\n\tdescription: 'sshd: authentication failed.'\n\tgroups: '[\"syslog\", \"sshd\", \"authentication_failed\"]'\n\tmitre.id: '[\"T1110.001\", \"T1021.004\"]'\n**Alert to be generated." },
        ],
        objectives: [
          { id: "dec", task: "Which decoder parsed the line?", hint: "Phase 2: name", answer: ["sshd"], why: "The program name in pre-decoding picked the sshd decoder, which knows where the user and address sit." },
          { id: "ip", task: "Which source address did the decoder extract?", hint: "Phase 2: srcip", answer: ["198.51.100.77"], why: "Once it's a field, rules can count it, correlate it and group it. Inside full_log it's just text." },
          { id: "user", task: "Which account was targeted?", hint: "Phase 2: dstuser", answer: ["root"], why: "A root login attempt on a build server from the internet: one failure is level 5, but a burst would trip a higher, frequency-based rule." },
        ],
      },
    ],
    // ── Reading 3: FIM and SCA ──
    "wazuh-r3": [
      {
        kind: "terminal",
        title: "Who Changed That File?",
        prompt: "An integrity alert fired on launcher-cdn-01, the server that will ship the game. Read it, then check the server's configuration score.",
        shell: "bash",
        host: "lucia@wz-manager-01:~$ ",
        commands: [
          { match: "(sudo\\s+)?(grep|jq|cat|tail).*alerts\\.json.*", help: "sudo grep '\"agent\":{\"id\":\"031\"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq '.rule, .syscheck'   the latest alert from agent 031",
            output: "{\n  \"id\": \"550\",\n  \"level\": 7,\n  \"description\": \"Integrity checksum changed.\"\n}\n{\n  \"path\": \"/etc/ssh/sshd_config\",\n  \"event\": \"modified\",\n  \"mode\": \"whodata\",\n  \"changed_attributes\": [\"size\", \"mtime\", \"md5\", \"sha256\"],\n  \"diff\": \"< PermitRootLogin no\\n---\\n> PermitRootLogin yes\",\n  \"audit\": { \"login_user\": { \"name\": \"j.marsh\" }, \"effective_user\": { \"name\": \"root\" }, \"process\": { \"name\": \"/usr/bin/vim.basic\" } }\n}" },
          { match: "(sudo\\s+)?(/var/ossec/bin/)?(sca|agent_control).*0?31.*|.*sca.*", help: "curl -sk -H \"Authorization: Bearer $TOKEN\" https://localhost:55000/sca/031   CIS benchmark result",
            output: "policy_id: cis_ubuntu22-04\nname:      CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0\npass:      141\nfail:      38\nscore:     78\nend_scan:  2026-11-04T00:30:12Z" },
        ],
        objectives: [
          { id: "file", task: "Which file changed?", hint: "The syscheck path", answer: ["/etc/ssh/sshd_config", "sshd_config"], why: "The SSH daemon's own configuration, on the server that ships the game." },
          { id: "setting", task: "Which setting flipped?", hint: "Read the diff", answer: ["permitrootlogin", "permitrootlogin yes", "permitrootlogin no to yes"], why: "Root may now log in over SSH directly. On an internet-facing CDN node, that's an open door." },
          { id: "who", task: "Which human was logged in when it changed?", hint: "whodata: audit.login_user", answer: ["j.marsh"], why: "Whodata names the person behind the sudo, not just root. Now you have someone to ask, and a change ticket to look for." },
        ],
      },
    ],
  },
};
