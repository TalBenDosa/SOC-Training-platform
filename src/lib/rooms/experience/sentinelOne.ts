import type { RoomExperience } from "./types";

// "Operation Rollback" for the "sentinelone" room.
// Script: docs/campaign/40-sentinelone.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Saltmarsh Brewing Co. (fictional), not the graded tasks' LAPTOP-JSMITH.
// Signature mechanic: reading a real-looking Threat Center status bar (inspect)
// before acting. Lab data differs from the graded tasks: the Threat Center
// never explains how Static AI judges a file (q4) or offers rollback; the
// Remote Shell hunt is a Linux persistence hunt that never isolates a host
// (q1); and nothing reads the LockBit detection (la1, flag1), mass renames or
// entropy (q2), Deep Visibility hunting (q3) or Detect versus Protect (q5).
export const SENTINEL_ONE: RoomExperience = {
  roomId: "sentinelone",
  codename: "Operation Rollback",
  theme: "s1",
  handler: { name: "Ingrid Solberg", role: "Endpoint Security Lead, Saltmarsh Brewing Co." },
  briefing: [
    "Saltmarsh Brewing Co. Three breweries, 60 pubs, and brewing recipes that a rival paid good money to try to steal last spring.",
    "Every laptop and server runs a SentinelOne Singularity agent. On Monday morning the console lit purple and red across the finance team.",
    "Ingrid Solberg leads endpoint security. She wants you to read the Threat Center before you touch a button, because every button there does something real.",
    "Learn the agent's engines, the Threat Center, Remote Shell and the response actions, then work a ransomware detection from start to finish.",
  ],
  mission: "Read a Threat Center status bar field by field, take a Remote Shell into a brewery server to find what keeps a miner alive, then work a ransomware detection and a rollout decision.",
  estimate: "~40 min",
  look: { primary: "#8b5cf6", secondary: "#22d3ee", warn: "#e5484d" },
  scene: "storyline",
  layout: "stage",
  stations: [
    {
      id: "center",
      label: "The Threat Center",
      topic: "Static AI, Behavioral AI and the cloud · the agent's verdicts and statuses",
      tagline: "Read before you click",
      building: "control",
      taskIds: ["s1-r1", "s1-q4"],
    },
    {
      id: "shell",
      label: "Remote Shell",
      topic: "Threats page, Storyline, Deep Visibility · Kill, Quarantine, Remediate, Rollback, Isolate",
      tagline: "Into the brewery server",
      building: "lab",
      taskIds: ["s1-r2", "s1-q1"],
    },
    {
      id: "ransom",
      label: "Ransomware",
      topic: "XDR, ransomware patterns and hunting across the fleet",
      tagline: "Know it when you see it",
      building: "vault",
      taskIds: ["s1-r3", "s1-q2", "s1-q3"],
    },
    {
      id: "monday",
      label: "Monday 09:14",
      topic: "A ransomware detection, field by field",
      tagline: "Work the critical one",
      building: "office",
      taskIds: ["s1-la1", "s1-flag1"],
    },
    {
      id: "rollout",
      label: "The Rollout",
      topic: "Detect Mode and Protect Mode",
      tagline: "Deploy without breaking the pubs",
      building: "ticket",
      taskIds: ["s1-q5"],
      boss: true,
    },
  ],
  personas: {
    "s1-q4": { name: "Ingrid Solberg", role: "Endpoint Security Lead", line: "One changed byte, a brand-new hash. How does the agent still stop it?" },
    "s1-q1": { name: "Ingrid Solberg", role: "Endpoint Security Lead", line: "A beacon every 60 seconds on a file server, and we don't know which process yet. First move?" },
    "s1-la1": { name: "Ingrid Solberg", role: "Endpoint Security Lead", line: "Critical, 09:14, finance laptop. Read it with me." },
    "s1-q5": { name: "Ingrid Solberg", role: "Endpoint Security Lead", line: "Two weeks to see what it would catch, without breaking the tills. Which mode?" },
  },
  briefings: {
    // ── Reading 1: signature mechanic, the Threat Center status bar ──
    "s1-r1": [
      {
        kind: "inspect",
        title: "Read the Threat Center",
        prompt: "A threat from the bottling plant's office PC this morning, as the Threat Center shows it. Open every part of the status bar and the details, and decide what still needs a human.",
        artifact: "Singularity · Threat Center · BREW-BTL-PC04 · keg_tracker_update.exe",
        items: [
          { id: "tstatus", text: "Threat Status: Mitigated (Killed, Quarantined)", tag: "Threat Status", tone: "trust", note: "The agent already acted: the process is dead and the file is in quarantine. The machine is safe from this file." },
          { id: "conf", text: "AI Confidence Level: Malicious", tag: "AI Confidence", tone: "warn", note: "The agent's own judgement. Malicious means it is sure; Suspicious would mean a human should look harder before trusting it." },
          { id: "verdict", text: "Analyst Verdict: Undefined", tag: "Analyst Verdict", tone: "warn", note: "Nobody has looked yet. Mitigated is the agent's work; the verdict is yours. True positive, false positive or suspicious: someone has to decide." },
          { id: "incident", text: "Incident Status: Unresolved", tag: "Incident Status", tone: "warn", note: "Still open. You close it only after you know how the file arrived and whether it ran anywhere else." },
          { id: "origin", text: "Originating process: OUTLOOK.EXE · user k.morgan · attachment 'Keg_Tracker_v3.zip'", tag: "Details", tone: "info", note: "How it got here: an email attachment. That points you at the mailbox next, and at everyone else who got the same mail." },
          { id: "agent", text: "Agent: 23.4.2 · Policy: Protect · Network: Connected", tag: "Endpoint", tone: "trust", note: "Current agent, protective policy, still reporting. Nothing on the endpoint itself needs fixing." },
        ],
      },
    ],
    // ── Reading 2: Remote Shell ──
    "s1-r2": [
      {
        kind: "terminal",
        title: "Remote Shell: the Brewery Server",
        prompt: "BREW-SRV-02 runs the fermentation controllers. A threat was mitigated last night, but CPU sits at 100% again this morning. Open a Remote Shell and find what brings it back.",
        shell: "bash",
        host: "root@brew-srv-02:~#",
        commands: [
          { match: "top\\s+-b\\s+-n\\s*1.*|top", help: "top -b -n 1 | head -12   what is using the CPU",
            output: "  PID USER      %CPU %MEM COMMAND\n 2211 brewctl   398.0  6.1 kthreaddk\n  904 brewctl     4.2  2.0 fermctl\n  611 root        0.4  0.3 sshd\n    1 root        0.0  0.1 systemd" },
          { match: "(systemctl\\s+list-units\\s+.*service.*|systemctl\\s+list-units)", help: "systemctl list-units --type=service --state=running",
            output: "UNIT                     LOAD   ACTIVE SUB     DESCRIPTION\nfermctl.service          loaded active running Fermentation controller\nkthreadd-helper.service  loaded active running Kernel thread helper\nsshd.service             loaded active running OpenSSH server daemon\nsentinelone.service      loaded active running SentinelOne agent" },
          { match: "(cat|systemctl\\s+cat)\\s+.*kthreadd-helper.*", help: "systemctl cat kthreadd-helper.service",
            output: "# /etc/systemd/system/kthreadd-helper.service\n[Unit]\nDescription=Kernel thread helper\n[Service]\nExecStart=/var/tmp/.k/kthreaddk -o pool.mining.example:3333\nRestart=always\nUser=brewctl\n[Install]\nWantedBy=multi-user.target" },
          { match: "ls\\s+-la?\\s+/var/tmp/\\.k/?", help: "ls -la /var/tmp/.k",
            output: "total 6120\ndrwxr-xr-x 2 brewctl brewctl    4096 Nov  4 23:58 .\n-rwxr-xr-x 1 brewctl brewctl 6262784 Nov  4 23:58 kthreaddk\n-rw-r--r-- 1 brewctl brewctl     211 Nov  4 23:58 config.json" },
        ],
        objectives: [
          { id: "proc", task: "Which process is eating the CPU?", hint: "top -b -n 1 | head -12", answer: ["kthreaddk", "2211"], why: "A name made to look like the kernel's kthreadd, running as an application user at 398% CPU. Real kernel threads don't belong to brewctl." },
          { id: "unit", task: "Which systemd service keeps restarting it?", hint: "systemctl list-units --type=service --state=running", answer: ["kthreadd-helper.service", "kthreadd-helper"], why: "Its description sounds harmless. Restart=always is why killing the process last night didn't stick." },
          { id: "where", task: "Which mining pool does it connect to?", hint: "systemctl cat kthreadd-helper.service", answer: ["pool.mining.example", "pool.mining.example:3333"], why: "A cryptominer. Remove the service and the hidden folder, not only the process, or it is back after the next restart." },
        ],
      },
    ],
  },
};
