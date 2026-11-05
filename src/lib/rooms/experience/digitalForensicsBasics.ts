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
        kind: "terminal",
        title: "Volatility on the Bidding Server",
        prompt: "The bidding server was still running, so Rosalind captured its RAM first. Interrogate the image with Volatility 3 and find the process that doesn't belong.",
        shell: "bash",
        host: "rosalind@ash-dfir:~/case0117$",
        commands: [
          { match: "(vol|vol\\.py|python3?\\s+vol\\.py)\\s+-f\\s+\\S+\\s+windows\\.pslist.*", help: "vol -f ASH-BID-01.mem windows.pslist",
            output: "PID    PPID   ImageFileName    CreateTime\n4      0      System           2026-10-14 06:02:11\n624    512    wininit.exe      2026-10-14 06:02:14\n704    624    services.exe     2026-10-14 06:02:14\n716    624    lsass.exe        2026-10-14 06:02:14\n2290   704    BidEngine.exe    2026-10-14 06:03:40\n3812   3790   explorer.exe     2026-10-14 08:11:52\n5124   3812   lsasss.exe       2026-10-14 21:47:03" },
          { match: "(vol|vol\\.py|python3?\\s+vol\\.py)\\s+-f\\s+\\S+\\s+windows\\.cmdline.*", help: "vol -f ASH-BID-01.mem windows.cmdline --pid 5124",
            output: "PID    Process     Args\n5124   lsasss.exe  \"C:\\Users\\Public\\Music\\lsasss.exe\" -bid-api https://203.0.113.71/api -lot 117" },
          { match: "(vol|vol\\.py|python3?\\s+vol\\.py)\\s+-f\\s+\\S+\\s+windows\\.pstree.*", help: "vol -f ASH-BID-01.mem windows.pstree",
            output: "* 624 wininit.exe\n** 704 services.exe\n*** 2290 BidEngine.exe\n** 716 lsass.exe\n* 3812 explorer.exe\n** 5124 lsasss.exe" },
        ],
        objectives: [
          { id: "name", task: "Which process name is pretending to be a system process?", hint: "vol -f ASH-BID-01.mem windows.pslist", answer: ["lsasss.exe", "5124"], why: "lsasss.exe, with three s's, started at 21:47. The real lsass.exe runs once, from wininit, since boot." },
          { id: "folder", task: "Which folder was it started from?", hint: "vol -f ASH-BID-01.mem windows.cmdline --pid 5124", answer: ["c:\\users\\public\\music", "public\\music", "c:\\users\\public\\music\\"], why: "A public music folder: no system binary lives there." },
          { id: "lot", task: "Which auction lot was it talking about?", hint: "Read the arguments", answer: ["117", "lot 117"], why: "Lot 117 is the Turner. The process was feeding bids to an outside API at 21:47 on auction night." },
        ],
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
    ],
  },
};
