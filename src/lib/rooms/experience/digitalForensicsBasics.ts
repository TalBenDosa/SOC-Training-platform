import type { RoomExperience } from "./types";

// "Operation Cold Case" for the "digital-forensics-basics" room.
// Script: docs/campaign/43-digital-forensics-basics.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Ashcombe Auction House (fictional), not the graded tasks' HOST-FINANCE.
// Signature mechanic: finding the faults on an evidence bag and its custody
// form. Lab data differs from the graded tasks: the custody form never puts
// collection steps in volatility order (q1, r1 checkpoint) or compares hashes
// (q2); the Volatility console examines a misspelled lsass, never svchost or
// its parent (q3, la1, flag1) and runs no malfind or netscan (q5, la1); and
// the timeline uses no Prefetch (q4).
export const DIGITAL_FORENSICS_BASICS: RoomExperience = {
  roomId: "digital-forensics-basics",
  codename: "Operation Cold Case",
  theme: "forensics2",
  handler: { name: "Rosalind Achebe", role: "Forensic Investigator, Ashcombe Auction House" },
  briefing: [
    "Ashcombe Auction House. 240 years old, a vault of fine art, and a bidding platform that moved £180 million last year.",
    "Three weeks ago the bids on a Turner painting were rigged. The insurer wants proof of who did it, and proof that holds up in court.",
    "Rosalind Achebe is the house's forensic investigator. To her, evidence that wasn't collected properly might as well not exist.",
    "Learn the order of volatility and chain of custody, memory forensics with Volatility, disk artefacts and timelines, then work a memory finding.",
  ],
  mission: "Find what's wrong on an evidence bag and its custody form, interrogate a memory image with Volatility 3, rebuild the night of the rigged auction from disk artefacts, then work the graded memory finding.",
  estimate: "~45 min",
  look: { primary: "#14b8a6", secondary: "#fbbf24", warn: "#f87171" },
  scene: "coldcase",
  layout: "stage",
  stations: [
    {
      id: "bag",
      label: "The Evidence Bag",
      topic: "Digital forensics · the order of volatility · chain of custody",
      tagline: "Evidence that holds up",
      building: "vault",
      taskIds: ["dfir-r1", "dfir-q1"],
    },
    {
      id: "memory",
      label: "Memory",
      topic: "What lives in RAM · capture tools · Volatility 3 plugins",
      tagline: "Read the machine's short-term memory",
      building: "lab",
      taskIds: ["dfir-r2", "dfir-q3"],
    },
    {
      id: "disk",
      label: "Disk and Timeline",
      topic: "Imaging and write blockers · MFT, Amcache, ShimCache, LNK, browser · Plaso",
      tagline: "Put the night back in order",
      building: "office",
      taskIds: ["dfir-r3", "dfir-q4"],
    },
    {
      id: "finding",
      label: "The Finding",
      topic: "A suspicious process in a memory image",
      tagline: "Work the graded finding",
      building: "control",
      taskIds: ["dfir-la1", "dfir-flag1"],
    },
    {
      id: "court",
      label: "Holds Up in Court",
      topic: "Proving integrity · reading malfind",
      tagline: "Make it stand up",
      building: "ticket",
      taskIds: ["dfir-q2", "dfir-q5"],
      boss: true,
    },
  ],
  personas: {
    "dfir-q1": { name: "Rosalind Achebe", role: "Forensic Investigator", line: "A colleague wants to image the disk first and dump RAM after. Stop them?" },
    "dfir-q3": { name: "Rosalind Achebe", role: "Forensic Investigator", line: "Four svchost.exe in memory. Which one is real?" },
    "dfir-la1": { name: "Rosalind Achebe", role: "Forensic Investigator", line: "pslist shows an svchost with an odd parent. Read it." },
    "dfir-q2": { name: "Rosalind Achebe", role: "Forensic Investigator", line: "Legal wants proof the RAM image hasn't changed in two weeks. What do we show them?" },
  },
  briefings: {
    // ── Reading 1: signature mechanic, the evidence bag ──
    "dfir-r1": [
      {
        kind: "hotspot",
        title: "What's Wrong With This Bag?",
        prompt: "The laptop from the bidding desk arrived in the lab in this bag, with this custody form. A defence lawyer will read both line by line. Tap everything that would let them question the evidence.",
        artifact: "Evidence bag ASH-2026-0117 · custody form",
        parts: [
          { id: "item", text: "Item: Dell Latitude 7440, serial 7K2M9Q3, bidding desk 2", flag: false, note: "A precise description with a serial number: exactly what should be here.", style: "meta" },
          { id: "seal", text: "Seal: tamper-evident seal #448120, intact", flag: false, note: "An intact, numbered seal shows nobody opened the bag in transit.", style: "meta" },
          { id: "gap", text: "Custody log: 14:10 R. Achebe (collected) → 14:25 courier → 09:40 next day lab (received)", flag: true, note: "Where was it overnight? Eighteen hours with no name against it is a gap a lawyer will drive a truck through.", style: "body" },
          { id: "unsigned", text: "Received by: ________ (unsigned)", flag: true, note: "Nobody signed for it at the lab. Every hand-over needs a name and a signature.", style: "body" },
          { id: "state", text: "State at collection: powered off by IT before collection", flag: true, note: "Someone handled the machine before the investigator arrived, and the form doesn't say who or when. Every touch before collection belongs on the record.", style: "body" },
          { id: "method", text: "Method: removed from desk, placed in anti-static bag, sealed in front of witness J. Park", flag: false, note: "A witnessed, described method: good practice.", style: "body" },
        ],
      },
    ],
    // ── Reading 2: memory ──
    "dfir-r2": [
      {
        kind: "deduce",
        title: "Which Process Is the Intruder?",
        prompt: "Rosalind captured RAM from the second bidding server, ASH-BID-02, while the auction was live. Six processes look odd at a glance. Strike out the ones that are normal and accuse the one that is not.",
        nameColumn: "Process",
        columns: ["Parent", "Started", "Connects to", "Image path"],
        suspects: [
          { id: "bid", name: "BidEngine.exe", cells: ["services.exe", "06:03", "10.20.4.12:1433", "D:\\Ashcombe\\Bid\\"] },
          { id: "spool", name: "spoolsv.exe", cells: ["services.exe", "06:02", "none", "C:\\Windows\\System32\\"] },
          { id: "winlogon", name: "winlogon.exe", cells: ["(parent exited)", "06:02", "none", "C:\\Windows\\System32\\"] },
          { id: "dllhost", name: "dllhost.exe", cells: ["svchost.exe", "21:49", "10.20.4.30:135", "C:\\Windows\\System32\\"] },
          { id: "edge", name: "msedge.exe", cells: ["explorer.exe", "21:44", "198.51.100.20:443", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\"] },
          { id: "rundll", name: "rundll32.exe", cells: ["explorer.exe", "21:50", "203.0.113.71:443", "C:\\Windows\\System32\\"] },
        ],
        clues: [
          "The auction opened at 21:30, and the intruder started after it opened, not at boot.",
          "Its traffic leaves the company network. Internal connections do not count.",
          "Volatility's module list shows it has a DLL mapped from C:\\ProgramData\\Intel\\cache\\, a folder no Windows component uses.",
        ],
        culprit: "rundll",
        why: "rundll32.exe is a genuine Windows binary in the genuine folder, so name and path clear nobody here. What convicts it is the combination: a user-session parent, a start after the auction opened, an outside address, and a DLL loaded from a folder no Windows component uses. winlogon.exe with an exited parent is normal (smss.exe hands off and quits), dllhost.exe only talks to an internal host, and msedge.exe talks outside but loads only its own modules.",
      },
    ],
    // ── Reading 3: disk and timeline ──
    "dfir-r3": [
      {
        kind: "sequence",
        title: "Rebuild the Night",
        prompt: "Artefacts from the bidding-desk laptop's disk image, each with its own timestamp. Tap them into the order they happened to rebuild auction night.",
        items: [
          { id: "lnk", text: "LNK (Recent Items): Lot117_reserve.xlsx opened from \\\\ASH-FS01\\Valuations at 21:31", note: "Opening a file leaves a shortcut with the target's path and times." },
          { id: "evtx", text: "Security 4624: bidding-desk logon by j.mercer, logon type 2, at 21:12", note: "Who sat down at the keyboard, and when." },
          { id: "browser", text: "Browser history: download of bidhelper.zip from 203.0.113.71 at 21:39", note: "The browser keeps what was fetched and from where." },
          { id: "mft", text: "$MFT: C:\\Users\\Public\\Music\\lsasss.exe created at 21:46", note: "The file system's own record of when the file appeared." },
          { id: "bin", text: "$Recycle.Bin: bidhelper.zip deleted at 22:05", note: "Deleted, but the bin kept the record of what and when." },
        ],
        order: ["evtx", "lnk", "browser", "mft", "bin"],
        doneNote: "Logon, reserve price opened, tool downloaded, dropped as a fake system process, archive deleted. One timeline, five artefacts, and every step has a timestamp of its own.",
      },
      {
        kind: "defuse",
        title: "Evidence Handling Under Pressure",
        prompt: "A second laptop and its drive arrive from the Ashcombe bidding desk, and the clock on the insurer's deadline is running. Each moment has one move that keeps the evidence admissible. Cut it.",
        device: "ASH-2026-0121 · acquisition bench",
        seconds: 90,
        rounds: [
          {
            id: "blocker",
            state: "The SSD is plugged straight into the lab workstation's dock. The OS pops up: 'This drive has errors. Scan and repair now?'",
            wires: [
              { id: "repair", label: "Accept the scan and repair, then image" },
              { id: "blocker", label: "Unplug, reconnect through a hardware write blocker" },
              { id: "ro", label: "Set the drive read-only in the OS disk settings" },
            ],
            cut: "blocker",
            hint: "Ask what actually stops writes if the OS misbehaves.",
            why: "Repairing writes to the suspect drive, and even mounting it can change timestamps and journals. A hardware write blocker is a control you can demonstrate in court; an OS setting depends on software you would also have to prove.",
          },
          {
            id: "copy",
            state: "The only complete image of the SSD sits on the evidence drive. A colleague wants to start carving files from it right now.",
            wires: [
              { id: "orig", label: "Search the image on the evidence drive directly" },
              { id: "rw", label: "Mount the original image read-write for speed" },
              { id: "work", label: "Make a verified working copy, search that" },
            ],
            cut: "work",
            hint: "The original is the one thing that can never be re-created.",
            why: "Analysis happens on a working copy so the original image stays untouched. Searching or mounting the original risks a change that cannot be undone, and read-write mounting writes metadata by design.",
          },
          {
            id: "bitlocker",
            state: "The laptop is on, the user is logged in, and the BitLocker volume is unlocked. No recovery key is on file. The room's power strip is being switched off at 18:00.",
            wires: [
              { id: "off", label: "Hold the power button now to freeze the disk as it is" },
              { id: "live", label: "Capture RAM and a live image of the unlocked volume first" },
              { id: "files", label: "Log in as admin and copy the lot files to a USB stick" },
            ],
            cut: "live",
            hint: "What becomes unreadable the moment this machine powers off?",
            why: "Powering off re-locks the volume, and without the key the disk is unreadable. The live capture keeps both RAM and the decrypted contents. Copying files by hand as admin changes the machine and skips the volatile data.",
          },
          {
            id: "clock",
            state: "At collection Rosalind noted the laptop clock was 14 minutes fast. Your timeline shows the payload file created at 21:46 by that clock.",
            wires: [
              { id: "edit", label: "Rewrite the timestamps on the evidence to true time" },
              { id: "note", label: "Record the 14 minute offset, correct only in the analysis copy" },
              { id: "trust", label: "Use the OS times as they are, since they are consistent" },
            ],
            cut: "note",
            hint: "Evidence may be annotated, never altered.",
            why: "The offset goes in the case notes and is applied on the working timeline, so every reader can see both values. Editing the evidence destroys it, and trusting a known-wrong clock puts the event at 21:46 when it really happened at 21:32.",
          },
        ],
        lesson: "Admissible evidence is protected twice: nothing writes to the original, and every correction or oddity is written in the notes, never into the evidence.",
      },
    ],
  },
};
