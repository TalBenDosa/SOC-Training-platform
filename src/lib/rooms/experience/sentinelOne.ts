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
  scene: "facilitysentinelone",
  layout: "facility",
  story: {
    intro: { title: "Purple Monday", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-intro-2cacc9d9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-intro-04c95e21.jpg" },
    afterStation: {
      center: { title: "Mitigated Is Not Finished", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-ch2-8c339cc9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-ch2-922c00b8.jpg" },
      shell: { title: "Restart=always", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-ch3-14ab3cc9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-ch3-90535d03.jpg" },
      rollout: { title: "Rewind", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-finale-09df0174.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinelone/rollback-finale-be899063.jpg" },
    },
  },
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
          { id: "agent", text: "Agent: 23.4.2 · Policy: Protect · Network: Connected", tag: "Endpoint", tone: "trust", note: "Current agent, protective policy, still reporting. Nothing on the endpoint itself needs fixing. Protect mode blocks and remediates on its own; Detect mode only raises the alert and leaves the action to a human." },
          { id: "engine", text: "Detected by: Static AI · pre-execution · file hash never seen before", tag: "Engine", tone: "info", note: "Static AI scores a file before it runs from its structural features, not from a signature, so a file with one changed byte and a brand-new hash is still caught. Behavioral AI is the other engine: it judges what a process does once it is running." },
          { id: "story", text: "Storyline ID: 0x7C41D2E9 · 6 events linked", tag: "Storyline", tone: "info", note: "Storyline tags every event of one attack chain with the same ID, so the mail attachment, the process and the file writes show up as one story instead of six separate alerts." },
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
        lesson: "Last night's mitigation killed a process but left the thing that starts it. Compare the unit with a known-good copy: the hidden path, the hidden working folder and Restart=always are the changes that matter. Version strings move with every patch. A 100% CPU process running as an application user and talking to a mining pool is a cryptominer, and the pool address sits in its config file. Remove the service entry and the folder as well as the process. The response actions: Kill stops a process, Quarantine moves the file aside, Remediate removes what the threat left behind, Rollback restores encrypted files, and Disconnect from Network isolates the host while the agent keeps reporting. Deep Visibility is the telemetry search across every endpoint that you hunt with.",
      },
    ],
    // ── Reading 3: ransomware and the fleet ──
    "s1-r3": [
      {
        kind: "sort",
        title: "Rollback Scope",
        prompt: "Ransomware has hit the pub-till network and is moving toward the backup server under the shared till admin account. Ingrid wants one decision per till before it gets there. Sort each host into the action it needs now.",
        buckets: [
          { id: "disconnect", label: "Disconnect from network now" },
          { id: "rollback", label: "Already cut off: Rollback its files" },
          { id: "trade", label: "Leave it trading" },
        ],
        items: [
          { id: "t04", text: "TILL-04 · the threat's process is still running and writing to the till's sales folder", bucket: "disconnect", why: "Infected and active: this is the host you cut off first. Disconnect from network stops it reaching other tills and the backup, and the agent keeps reporting while you work." },
          { id: "t11", text: "TILL-11 · the dropper started ten minutes ago under the shared till admin account; no files changed yet", bucket: "disconnect", why: "Nothing is encrypted yet, but it is infected. Cutting it off now is cheaper than rolling it back later." },
          { id: "t02", text: "TILL-02 · disconnected at 21:14, threat killed and quarantined, 3,900 sales files still encrypted", bucket: "rollback", why: "Mitigated is not finished. The spread is stopped and the threat is dead, so Rollback now restores the encrypted files from the pre-attack snapshot." },
          { id: "t09", text: "TILL-09 · disconnected at 21:16, threat killed, every encrypted file still in its new form", bucket: "rollback", why: "Same state as TILL-02: contained and mitigated, files not yet restored. Rollback comes after the host is cut off and the threat is dead, never instead of it." },
          { id: "t06", text: "TILL-06 · no detections, and the till admin account has not logged on to it since Monday", bucket: "trade", why: "No sign of infection and no logon by the spreading account. Quarantining it would only close a pub." },
          { id: "t13", text: "TILL-13 · same pub and same switch as TILL-04, no detections, no logon from an infected till", bucket: "trade", why: "Being next to an infected till is not infection. The spread travels on the shared admin account, and that account never reached this till." },
        ],
      },
      {
        kind: "chat",
        title: "Hold the Line With Ingrid",
        prompt: "21:40 on the incident bridge. Ingrid has your sort and three quick proposals before she messages the pub managers. Answer each one: tap a message to see how it lands, or write your own.",
        bot: "Ingrid Solberg",
        botRole: "IT Lead, Saltmarsh Brewing Co. · incident bridge",
        greeting: "I've got your sort. Three things before I message the pubs, and I want a straight answer on each.",
        fallback: "Give me the call and the reason. Which host, and what do we do with it?",
        rules: [
          { match: "^\\W*(yes|sure|ok|okay|go ahead)\\b|roll ?back (it |till-?04 )?(now|first|straight away)", goal: "order", reply: "If we roll back while its process is still running and the network is open, it just encrypts the restored files again, and keeps reaching for the other tills. What has to happen to TILL-04 first?" },
          { match: "disconnect|cut (it )?off|isolate|network quarantine", goal: "order", wins: true, reply: "Right. Cut it off first, so it stops reaching other tills and the backup while the agent keeps reporting. Kill it, then Rollback, once nothing is fighting the restore." },
          { match: "\\b(no|don'?t|do not|keep|leave)\\b.*(trad|open|online|running|connected)|no (detection|logon)|never (logged|reached|touched)|not infected", goal: "fear", wins: true, reply: "Fair. The spread rides the shared admin account, not the switch, and that account never reached TILL-13. It stays open and keeps trading." },
          { match: "yes|disconnect|quarantine|isolate|just in case", goal: "fear", reply: "That closes a pub on a guess. What would actually tell us TILL-13 is infected?" },
          { match: "account|password|credential|disable|reset|rotate", goal: "account", wins: true, reply: "Agreed. Every infected till was reached with that one account. I'll have it disabled tonight and a separate password issued per pub." },
          { match: "safe|nothing|done|no\\b", goal: "account", reply: "Every infected till was reached the same way. What did it use to get from one till to the next, and does that still work?" },
        ],
        goals: [
          {
            id: "order",
            task: "Ingrid: \"TILL-04 is still encrypting. Let's run Rollback on it right now and disconnect it afterwards.\" Answer her.",
            tries: ["Yes, roll back TILL-04 now and disconnect it later", "No: disconnect TILL-04 first, then kill it. Rollback only once the threat is dead"],
            why: "The infected host is the one you cut off first. Rollback restores files, it does not stop the process doing the encrypting, so it comes after the host is disconnected and the threat is killed.",
          },
          {
            id: "fear",
            task: "Ingrid: \"TILL-13 is on the same switch as TILL-04. Let's disconnect it too, just in case.\" Answer her.",
            tries: ["Yes, disconnect everything near TILL-04", "No: it has no detections and the shared admin account never logged on to it, so it keeps trading"],
            why: "Disconnect the hosts that show infection or the spreading account's logons, not the ones that are merely nearby. Every clean till you cut off is a pub that cannot trade.",
          },
          {
            id: "account",
            task: "Ingrid: \"Every infected till is cut off now. Is there anything else the spread could still use?\" Answer her.",
            tries: ["No, we're safe now", "The shared till admin account: disable it and reset its password, or it can reach the next till"],
            why: "Cutting off hosts stops the copies you already know about. The shared credential is how it moved, and it still works on every till until someone disables it.",
          },
        ],
        doneNote: "Contain the infected host first, Rollback after the threat is dead, leave clean tills trading, and take away the account the spread travels on.",
      },
    ],
  },
};
