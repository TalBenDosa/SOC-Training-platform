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
  mission: "Read a Threat Center status bar field by field, compare a brewery server with its gold image to find what keeps a miner alive, then work a ransomware detection and a rollout decision.",
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
        kind: "spotdiff",
        title: "Remote Shell: the Unit File Before and After",
        prompt: "BREW-SRV-04 runs the cellar temperature logger. A threat there was mitigated last night, yet CPU is pinned again this morning. In a Remote Shell you open the logger's service unit on the left, and the same unit from its gold image on the right. Tap the lines that were tampered with.",
        goodTitle: "Gold image · templog.service",
        suspectTitle: "BREW-SRV-04 · systemctl cat templog.service",
        good: [
          "# /etc/systemd/system/templog.service",
          "[Unit]",
          "Description=Cellar temperature logger",
          "After=network.target",
          "[Service]",
          "ExecStart=/opt/brewctl/bin/templogd --config /etc/brewctl/templog.conf",
          "WorkingDirectory=/opt/brewctl",
          "Restart=on-failure",
          "User=brewctl",
          "[Install]",
          "WantedBy=multi-user.target",
          "# package: templog 2.3.1",
        ],
        suspect: [
          "# /etc/systemd/system/templog.service",
          "[Unit]",
          "Description=Cellar temperature logger (patched)",
          "After=network.target",
          "[Service]",
          "ExecStart=/var/tmp/.k/templogd --config /var/tmp/.k/config.json",
          "WorkingDirectory=/var/tmp/.k",
          "Restart=always",
          "User=brewctl",
          "[Install]",
          "WantedBy=multi-user.target",
          "# package: templog 2.3.2",
        ],
        diffs: [
          { line: 5, why: "ExecStart now points into a hidden folder under /var/tmp, not the packaged /opt/brewctl/bin. That is the miner, wearing the logger's service name." },
          { line: 6, why: "The working directory moved to the same hidden folder. Remediate must remove this folder and its files, not only stop the process." },
          { line: 7, why: "Restart=always is why killing the process last night did not stick: systemd starts it again within seconds. The gold image restarts only on failure." },
        ],
        decoys: [
          { line: 2, why: "The word patched in the description comes with a routine package update. Check the package line, then the paths, before you suspect it." },
          { line: 11, why: "The package comment moved from 2.3.1 to 2.3.2, matching the last patch window. It changes no behaviour." },
        ],
        lesson: "Last night's mitigation killed a process but left the thing that starts it. Compare the unit with a known-good copy: the hidden path, the hidden working folder and Restart=always are the changes that matter. Version strings move with every patch. A 100% CPU process running as an application user and talking to a mining pool is a cryptominer, and the pool address sits in its config file. Remove the service entry and the folder as well as the process.",
      },
    ],
    // ── Reading 3: ransomware and the fleet ──
    "s1-r3": [
      {
        kind: "outbreak",
        title: "Rollback Scope",
        prompt: "Ransomware has reached the pub-till network, and it is moving toward the backup server. Ingrid wants Network Quarantine on one host a turn, the backup untouched, and as many clean tills trading as possible.",
        hostPrefix: "TILL",
        cols: 6,
        rows: 5,
        crown: "BACKUP",
        via: "the shared till admin account",
        lesson: "Scope comes before any button. Network Quarantine (Disconnect from network) stops the spread while the agent keeps reporting, and only after that does Rollback make sense on the hosts that were actually encrypted. Do not quarantine clean tills out of fear: every pub that cannot trade is a cost, so cut at the point that protects the most.",
      },
    ],
  },
};
