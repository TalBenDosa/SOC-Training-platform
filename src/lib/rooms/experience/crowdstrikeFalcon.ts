import type { RoomExperience } from "./types";

// "Operation Talon" for the "crowdstrike-falcon" room.
// Script: docs/campaign/39-crowdstrike-falcon.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Brightmoor Hotels (fictional), not the graded tasks' CORP. Signature
// mechanic: a policy simulator (Prevent vs Insight). Lab data differs from the
// graded tasks: the simulator never runs a brand-new executable straight into
// a block (r1 checkpoint); the console screens show no driver loading and no
// OverWatch detection (q2, q3); the RTR console never uses get (q4) or decodes
// an encoded PowerShell (q1); and nothing reads the LSASS dump (la1, flag1),
// PsExec fan-out (q5) or a Word-to-PowerShell chain (ac1).
export const CROWDSTRIKE_FALCON: RoomExperience = {
  roomId: "crowdstrike-falcon",
  codename: "Operation Talon",
  theme: "falcon",
  handler: { name: "Tobias Wren", role: "EDR Lead, Brightmoor Hotels" },
  briefing: [
    "Brightmoor Hotels. 46 hotels, 3,900 staff, front-desk PCs in every lobby and card data on every one of them.",
    "Every Brightmoor endpoint runs the CrowdStrike Falcon sensor. Tonight a night auditor's laptop in Lisbon is calling a server nobody recognises.",
    "Tobias Wren runs EDR from the London office. He can't walk to Lisbon, and he doesn't need to.",
    "Learn what the sensor and the cloud each do, read the Falcon console, take a host apart remotely with Real Time Response, then work the detections that matter.",
  ],
  mission: "Run files through Falcon's prevention and detection policy, name what each console screen shows, drive a Real Time Response session to find, trace and kill a beacon, then work a credential-dumping detection and a verdict.",
  estimate: "~45 min",
  look: { primary: "#ef4444", secondary: "#f8fafc", warn: "#f59e0b" },
  scene: "talon",
  layout: "stage",
  stations: [
    {
      id: "console",
      label: "The Falcon Console",
      topic: "Sensor and cloud · Prevent and Insight · detections, host management, OverWatch",
      tagline: "Know what the sensor stops and what it reports",
      building: "control",
      taskIds: ["cs-falcon-r1", "cs-falcon-r2", "cs-falcon-q3"],
    },
    {
      id: "rtr",
      label: "Real Time Response",
      topic: "A remote shell through the sensor · contain host · common attack patterns",
      tagline: "Reach Lisbon from London",
      building: "lab",
      taskIds: ["cs-falcon-r3", "cs-falcon-q1", "cs-falcon-q2", "cs-falcon-q4"],
    },
    {
      id: "dump",
      label: "Memory Theft",
      topic: "A credential-dumping detection, field by field",
      tagline: "Read the critical one",
      building: "vault",
      taskIds: ["cs-falcon-la1", "cs-falcon-flag1"],
    },
    {
      id: "keyboard",
      label: "Hands on Keyboard",
      topic: "From one host to five · a verdict on a lobby PC",
      tagline: "Call the last two",
      building: "ticket",
      taskIds: ["cs-falcon-q5", "cs-falcon-ac1"],
      boss: true,
    },
  ],
  personas: {
    "cs-falcon-q3": { name: "Tobias Wren", role: "EDR Lead", line: "Nobody was on shift at 03:00, yet there's a written analysis in the console. Who wrote it?" },
    "cs-falcon-q2": { name: "Tobias Wren", role: "EDR Lead", line: "A new driver, then the sensor goes quiet. Glitch or attack?" },
    "cs-falcon-q4": { name: "Tobias Wren", role: "EDR Lead", line: "I need that file from Lisbon. How do we get it?" },
    "cs-falcon-la1": { name: "Tobias Wren", role: "EDR Lead", line: "Critical on a domain controller at 23:47. Read it with me." },
    "cs-falcon-ac1": { name: "Tobias Wren", role: "EDR Lead", line: "Word launching PowerShell on a finance PC. Your verdict." },
  },
  briefings: {
    // ── Reading 1: sensor, cloud, Prevent and Insight. Signature mechanic. ──
    "cs-falcon-r1": [
      {
        kind: "simulate",
        title: "Prevent or Detect?",
        prompt: "Four things that ran on Brightmoor endpoints this week. Run each through the sensor's checks and see whether Falcon Prevent blocked it, Falcon Insight raised a detection, or both let it run.",
        checks: [
          { name: "ML score", question: "Is the file's machine-learning score above the block threshold?" },
          { name: "Known bad", question: "Is its hash on CrowdStrike's known-malicious list?" },
          { name: "Behaviour", question: "Does what it does after starting match an attack pattern (an IOA)?" },
        ],
        scenarios: [
          { id: "tool", label: "IT's signed remote-support tool", detail: "Run by the helpdesk on a lobby PC during a ticketed session.", results: ["fail", "fail", "fail"], why: ["Signed, widely used, low score.", "Not known-bad.", "Nothing after start matches an attack pattern."], verdict: "Allowed, and recorded. Prevention and detection both stay quiet; the telemetry is still there if you ever need it." },
          { id: "macro", label: "A known banking trojan in an email attachment", detail: "A finance clerk opens a ZIP from 'Brightmoor Payroll'.", results: ["pass", "pass", "fail"], why: ["High score from the model.", "The hash is already on the known-bad list.", "It never got far enough to behave."], verdict: "Blocked by Prevent before it ran. Nothing for an analyst to chase, but worth asking why it reached the inbox." },
          { id: "lolbin", label: "rundll32 loading a DLL from Downloads at 03:10", detail: "On a night auditor's laptop, followed by a connection to an unknown server.", results: ["fail", "fail", "pass"], why: ["rundll32 is a signed Windows binary: no file to score.", "Nothing known-bad to match.", "A signed binary loading code from Downloads, then calling out, is an attack pattern."], verdict: "Detected by Insight. Prevent had nothing to block; behaviour is what gave it away. This is the analyst's work." },
          { id: "script", label: "A backup script that copies a database at midnight", detail: "Same script, same server, every night for two years.", results: ["fail", "fail", "fail"], why: ["A script, not a scored file.", "Not known-bad.", "Copying a file is not an attack pattern by itself."], verdict: "Allowed. If it ever started compressing and uploading the copy somewhere new, the behaviour check would change its answer." },
        ],
      },
    ],
    // ── Reading 2: the console ──
    "cs-falcon-r2": [
      {
        kind: "evidence",
        title: "Which Screen Is This?",
        prompt: "Three Falcon console screens from tonight. Name what each one is telling you, then read the numbered clues.",
        choices: [
          { id: "health", label: "Host Management: a sensor's health" },
          { id: "intel", label: "Threat intelligence on an indicator" },
          { id: "auto", label: "An automated response that ran" },
        ],
        items: [
          {
            id: "host",
            caption: "Falcon · Host Management · BMH-LIS-NA07",
            screen: { type: "status", service: "Falcon sensor · BMH-LIS-NA07 (night auditor, Lisbon)", state: "Online · last seen 14 s ago · sensor 7.18", errors: "Prevention policy: Hotels-Standard · RFM: off", series: [40, 42, 39, 44, 41, 43, 120, 135, 128] },
            answer: "health",
            callouts: [
              { at: "state", text: "Online and checked in seconds ago: the sensor is healthy and still talking to the cloud. That is what makes remote response possible." },
              { at: "graph", text: "Event volume jumped late in the night. A healthy sensor reporting more, not less, often means the host is busy doing something new." },
            ],
          },
          {
            id: "ioc",
            caption: "Falcon · Intel · Indicator 198.51.100.66",
            screen: { type: "tip", indicator: "198.51.100.66", kind: "IPv4", score: "High confidence · malicious", tags: ["c2", "commodity-loader", "first seen 6 days ago"], sightings: ["Contacted by 1 host in your environment: BMH-LIS-NA07", "Seen by 214 other CrowdStrike customers this week"] },
            answer: "intel",
            callouts: [
              { at: "indicator", text: "The address the Lisbon laptop keeps calling." },
              { at: "score", text: "Cloud-wide intelligence already calls it command and control: one customer's sighting protects the rest within seconds." },
              { at: "sightings", text: "Only one Brightmoor host has touched it so far. Contain the scope while it's one." },
            ],
          },
          {
            id: "wf",
            caption: "Falcon Fusion · workflow run · 03:14",
            screen: { type: "soarrun", playbook: "Hotels: high-severity detection on a payment PC", trigger: "Detection severity High on host group Front-Desk", steps: [{ name: "Tag host 'under-investigation'", result: "done", ok: true }, { name: "Page EDR on-call (T. Wren)", result: "acknowledged 03:16", ok: true }, { name: "Network contain host", result: "skipped: needs analyst approval", ok: false }] },
            answer: "auto",
            callouts: [
              { at: "trigger", text: "Fired because a high detection landed on a card-handling PC." },
              { at: "steps", text: "Tagging and paging are automatic; containment waits for a human. Cutting a front-desk PC off is a business decision." },
            ],
          },
        ],
      },
    ],
    // ── Reading 3: RTR ──
    "cs-falcon-r3": [
      {
        kind: "terminal",
        title: "Remote Shell to Lisbon",
        prompt: "Real Time Response session to BMH-LIS-NA07, opened from London through the sensor. Find the process calling out, see where it goes, find what restarts it, and stop it.",
        shell: "cmd",
        host: "RTR BMH-LIS-NA07>",
        commands: [
          { match: "ps", help: "ps   list running processes",
            output: "Name                PID    Path\n----                ---    ----\nexplorer.exe        3108   C:\\Windows\\explorer.exe\nNightAudit.exe      5220   C:\\Program Files\\Brightmoor\\NightAudit\\NightAudit.exe\nOneDrive.exe        6012   C:\\Users\\r.sousa\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\nupdsvc.exe          4412   C:\\Users\\Public\\Libraries\\updsvc.exe\nmsedge.exe          7104   C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" },
          { match: "netstat", help: "netstat   active network connections",
            output: "Proto  Local Address          Foreign Address        State        PID\nTCP    10.46.12.31:52811      198.51.100.66:443      ESTABLISHED  4412\nTCP    10.46.12.31:52790      10.46.0.20:443         ESTABLISHED  5220\nTCP    10.46.12.31:52802      52.96.0.10:443         ESTABLISHED  6012" },
          { match: "reg\\s+query\\s+\"?hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\"?", help: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run   what starts at logon",
            output: "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n    OneDrive    REG_SZ    \"C:\\Users\\r.sousa\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background\n    UpdSvc      REG_SZ    C:\\Users\\Public\\Libraries\\updsvc.exe" },
          { match: "kill\\s+4412", help: "kill 4412   stop a process by its PID",
            output: "Process 4412 (updsvc.exe) killed." },
        ],
        objectives: [
          { id: "pid", task: "Which process ID is running from a public folder?", hint: "ps", answer: ["4412"], why: "updsvc.exe in C:\\Users\\Public\\Libraries: no installed software lives there." },
          { id: "dest", task: "Which outside address is that process connected to?", hint: "netstat", answer: ["198.51.100.66", "198.51.100.66:443"], why: "The address the intel screen already called command and control." },
          { id: "back", task: "Which Run value would start it again at the next logon?", hint: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", answer: ["updsvc"], why: "Kill the process and it comes back at logon unless you remove UpdSvc too. Then kill 4412." },
        ],
      },
    ],
  },
};
