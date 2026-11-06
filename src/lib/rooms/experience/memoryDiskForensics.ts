import type { RoomExperience } from "./types";

// "Operation Pagefile" for the "memory-disk-forensics" room.
// Script: docs/campaign/79-memory-disk-forensics.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Harrowgate Museum Trust (fictional), not the graded tasks' HOST-ACCT-19 or SOLVIX records.
// Mentor: Yusra Lindahl, DFIR Analyst.
// Signature, Two Timelines: room 43 names the artefacts, this room reads them against each other.
// Two traces put Volatility 3 output (windows.pslist, windows.mftscan.MFTScan, windows.netscan)
// beside parsed disk artefacts ($MFT, $UsnJrnl, Prefetch, ShimCache, Amcache) until a back-dated
// file gives itself away because $STANDARD_INFORMATION and $FILE_NAME disagree. The museum reading
// runs through it: a label on a case can say anything, so check it against the register.
// Game mix: codebreak + defuse + tune.
//
// TASK ORDER CHANGED. The room has f1 at the very end, far from the log it refers to, and ac1 in
// the middle, though it is the room's hardest call and reverses what r5 teaches. New order, for
// the integrator:
//   mdf-r1, mdf-r2, mdf-q1, mdf-r3, mdf-q2 | mdf-r4, mdf-la1, mdf-f1 | mdf-r5, mdf-m1, mdf-q3 |
//   mdf-r6, mdf-o1 | mdf-ac1
//
// Hosts: HMT-REG-07 and HMT-CON-03 are workstations with no EDR agent. HMT-FS-02, HMT-COLL-01,
// HMT-IMG-01 and HMT-APP-03 are servers with one. Telemetry in the labs respects that.
//
// Lab data differs from the graded tasks: the first-step idea is taught through the stopgap case,
// a dump that cannot start yet, never the plain "what first?" of r1; the memory-only item is a
// packed loader's list of file extensions, never a C2 domain and key (q1); the custody record is
// for a memory dump only and never asks about a live disk image or a colleague's challenge (r3, q2); the
// back-dated file is clsync32.exe in ProgramData with a 225 second gap, never quarterly_report.exe
// in Downloads with 107 (la1, f1); the worksheet asks 75 and 95 (f1); the cleared logs are System,
// Application and PowerShell with Event ID 104, found from a firewall alert, never Security with
// 1102 or an all-channel clear (q3, m1, r5); the survivor
// drill uses other erasers: del of Prefetch, SDelete, fsutil usn deletejournal (m1); the defuse
// makes single calls on separate hosts and never asks an order (o1); the boss warm-up uses
// sdelete, fsutil, cipher and a read-only vssadmin list, never a backup job deleting shadow copies
// (ac1).

export const MEMORY_DISK_FORENSICS: RoomExperience = {
  roomId: "memory-disk-forensics",
  codename: "Operation Pagefile",
  theme: "pagefile",
  handler: { name: "Yusra Lindahl", role: "DFIR Analyst, Harrowgate Museum Trust" },
  briefing: [
    "Harrowgate Museum Trust. Five museums, one collections database, and nine days until the Kestrel Hoard goes on display.",
    "A file on the registrar's workstation says it was created in 2017, among the old catalogue software. The registrar says nobody has opened that folder in years.",
    "Yusra Lindahl has a write-protected USB, a machine that is still running, and a suspicion: someone has forged this file's label, the way a dealer forges provenance.",
    "Take the image, read memory beside disk, find what the erasers missed, and decide when to pull the plug.",
  ],
  mission: "Collect from a live machine, name what only memory holds, find the holes in a custody record, read Volatility output beside the $MFT, $UsnJrnl, Prefetch, ShimCache and Amcache, tune a sweep, follow an eraser across sources, make the calls under fire, then rule on the last alert.",
  estimate: "~65 min",
  look: { primary: "#d6b370", secondary: "#7cc6b8", warn: "#ff5964" },
  scene: "facilitypagefile",
  layout: "facility",
  stations: [
    {
      id: "image",
      label: "The Image",
      topic: "Live acquisition · what only memory holds · hashing and custody on a running host",
      tagline: "Touch it once, and write it down",
      building: "lab",
      taskIds: ["mdf-r1", "mdf-r2", "mdf-q1", "mdf-r3", "mdf-q2"],
    },
    {
      id: "timelines",
      label: "Two Timelines",
      topic: "$STANDARD_INFORMATION and $FILE_NAME · $UsnJrnl · $LogFile · Prefetch, ShimCache, Amcache · cross-source correlation",
      tagline: "One file, two birthdays",
      building: "archive",
      taskIds: ["mdf-r4", "mdf-la1", "mdf-f1"],
    },
    {
      id: "behind",
      label: "What Stays Behind",
      topic: "Cleared logs · timestomping · shadow copy deletion · where each erasure gets recorded",
      tagline: "An empty log is a timestamp",
      building: "vault",
      taskIds: ["mdf-r5", "mdf-m1", "mdf-q3"],
    },
    {
      id: "plug",
      label: "Pull the Plug",
      topic: "Preserving evidence against stopping damage · deciding factors · escalation",
      tagline: "Every containment costs something",
      building: "emergency",
      taskIds: ["mdf-r6", "mdf-o1"],
    },
    {
      id: "shadow",
      label: "The Last Shadow",
      topic: "Weighing process, account, scope and change records into one verdict",
      tagline: "One more alert before the doors open",
      building: "ticket",
      taskIds: ["mdf-ac1"],
      boss: true,
    },
  ],
  personas: {
    "mdf-q1": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "A case stalled six months in. Tell me where it went wrong." },
    "mdf-q2": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "A colleague has challenged an image. How do you answer?" },
    "mdf-la1": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "Two sets of dates on one record. Read both before you say anything." },
    "mdf-f1": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "The case note needs a number. Work it out from the record." },
    "mdf-m1": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "Pair these up for the report." },
    "mdf-q3": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "A colleague has given up on this host. What now?" },
    "mdf-o1": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "You're mid-triage and the screen has changed. Put your next steps in order." },
    "mdf-ac1": { name: "Yusra Lindahl", role: "DFIR Analyst", line: "Last alert of the week. Your verdict, with your reasons." },
  },
  briefings: {
    // ── Reading 1: a small, known, documented footprint ──
    "mdf-r1": [
      {
        kind: "defuse",
        title: "Hands on a Live Machine",
        prompt: "HMT-REG-07 is still running on the registrar's desk, and Yusra has handed you the kit: a write-protected USB and a collection drive. Memory changes while you think. Read each state and cut the wire that keeps the scene defensible.",
        device: "Live response kit · HMT-REG-07",
        seconds: 90,
        primer: {
          title: "Your footprint on a running machine",
          points: [
            "Every program you start changes the host: a new process in RAM, perhaps a Prefetch entry, touched access times. The aim is a **small, known, documented** footprint, because zero is impossible.",
            "Run trusted, statically linked tools from **read-only external media**, so you depend on no DLL from a machine that may be compromised.",
            "A memory image holds more than people expect: `windows.netscan` and `windows.pslist` read sockets and processes straight out of one.",
            "DumpIt and winpmem are built to run standalone from removable media, with no setup step.",
          ],
          example: {
            label: "The method, on a gallery kiosk last spring",
            lines: [
              "State: kiosk running, USB mounted, collection drive large enough.",
              "Notebook first: `14:02 UTC, E:\\winpmem_mini_x64.exe F:\\KIOSK-03.raw`, tool version, analyst name.",
            ],
          },
          fold: true,
        },
        rounds: [
          {
            id: "wizard",
            state: "The imager in the top folder of your USB is a GUI product with a setup wizard. A portable winpmem build sits in a subfolder.",
            wires: [
              { id: "install", label: "Run the signed setup wizard" },
              { id: "copy", label: "Copy the portable build to C:\\Temp, run it there" },
              { id: "usb", label: "Run the portable build from the USB, write to the collection drive" },
            ],
            cut: "usb",
            hint: "Which choice writes nothing to the target's own disk?",
            why: "A signed installer is still an installer: it writes registry keys and Prefetch entries. Copying to C:\\Temp overwrites free space that may hold evidence. Running from the USB and writing to your own drive keeps the footprint small and known.",
          },
          {
            id: "space",
            state: "This host has 32 GB of RAM. The collection drive in your kit holds 16 GB. A bigger drive arrives in 25 minutes, and a live connection on this host may be gone by then.",
            wires: [
              { id: "local", label: "Write the dump to the host's own C: drive now" },
              { id: "snapshot", label: "Take a quick connection and process snapshot from the USB, then dump when the drive arrives" },
              { id: "wait", label: "Run nothing at all for 25 minutes" },
            ],
            cut: "snapshot",
            hint: "Can a full dump start at all right now? What is the least you can do meanwhile?",
            why: "The dump genuinely cannot start, so a snapshot from trusted tools is the right stopgap, logged as such. Writing 32 GB to C: overwrites deleted data on the very disk you still need. Waiting loses the connection for nothing.",
          },
          {
            id: "netstat",
            state: "Time for that snapshot. The host's own C:\\Windows\\System32\\netstat.exe is one keystroke away, and it is signed by Microsoft. Your USB carries a trusted command line equivalent.",
            wires: [
              { id: "tool", label: "Run the trusted tool from the USB" },
              { id: "signed", label: "Run the host's netstat: the signature makes it safe" },
              { id: "gui", label: "Open Task Manager and photograph the Performance tab" },
            ],
            cut: "tool",
            hint: "A signature describes one file. What else does a program load when it runs?",
            why: "A signed binary on a suspect host still loads that host's DLLs, and a rootkit can lie to it. Your own tool from read-only media leaves less to doubt. Task Manager walks the same list a rootkit edits.",
          },
          {
            id: "notes",
            state: "The bigger drive is here. The dump is ready to launch, your notebook page is empty, and the director is asking for an update.",
            wires: [
              { id: "later", label: "Launch now, write it up from memory tonight" },
              { id: "history", label: "Launch now, recover the commands from shell history later" },
              { id: "first", label: "Write the command, UTC time and tool version, then launch" },
            ],
            cut: "first",
            hint: "When does a note count as evidence of what you did?",
            why: "A contemporaneous note is what makes your actions defensible to a sceptical reviewer or in a legal case. A note from memory is disputable, and shell history is not a record you control on a suspect machine.",
          },
        ],
        lesson: "Live response is not about leaving no trace. It is about leaving a trace you chose, can explain, and wrote down before you made it.",
      },
    ],

    // ── Reading 2: what memory yields that disk cannot ──
    "mdf-r2": [
      {
        kind: "codebreak",
        title: "Name the Volatility Plugin",
        prompt: "Yusra's image of HMT-REG-07 is on the analysis box. Each clue is a question the image can answer. Name the Volatility 3 plugin that answers it. Type only the part after 'windows.' in its name.",
        primer: {
          title: "What memory shows, and which plugin shows it",
          points: [
            "Legitimate code loads from a file you can hash. **Injected** code sits in private memory with execute rights and no file behind it, inside a normal process, so a disk image has nothing to find. `malfind` lists such regions.",
            "Malware often ships encrypted and must decrypt itself to run. Its plaintext strings, keys and settings exist in RAM while it runs, not in the file on disk.",
            "`netscan` recovers sockets with the process that owned each one, at the instant of capture. A firewall log may hold only a stripped flow, or nothing once it rotates.",
            "`pslist` walks the operating system's own process list, which a rootkit can edit (DKOM, Direct Kernel Object Manipulation). `psscan` searches memory for the EPROCESS signature, linked into the list or not.",
            "`cmdline` gives each process's arguments, and `handles` its open files, registry keys and mutexes (shown as type `Mutant`).",
          ],
          example: {
            label: "The method, on another question",
            lines: [
              "Question: which services did the host know about at capture?",
              "The answer is in RAM, in the service manager's records.",
              "Plugin: `windows.svcscan`. Columns: `Offset Order PID Start State Type Name Display Binary`.",
            ],
          },
          fold: true,
        },
        rounds: [
          { id: "inject", clue: "svchost.exe owns a region with PAGE_EXECUTE_READWRITE rights, tag VadS, and no mapped file. Which plugin surfaces regions like that?", answer: "MALFIND", why: "windows.malfind flags private regions with execute rights and no backing file. A hit is a lead to check, since some JIT compilers do the same, but this class of evidence has no equivalent on disk." },
          { id: "socket", clue: "The proxy log rotated hours ago. You want the far address of a short session and the process that held it.", answer: "NETSCAN", why: "windows.netscan prints LocalAddr, ForeignAddr, State, PID, Owner and Created, tying the socket to a process in one row. A flow record alone cannot do that." },
          { id: "args", clue: "An archiver is running, and the operator typed the archive password in full when launching it. Which plugin shows each process's arguments?", answer: "CMDLINE", why: "windows.cmdline reads each process's arguments from its memory, so a password typed on a command line can be sitting in plain text with no process logging on the host." },
          { id: "mutant", clue: "A threat report says one family holds a named mutex. Which plugin lists the objects each process has open?", answer: "HANDLES", why: "windows.handles lists PID, Process, Type and Name for open objects. Filter on Type Mutant to test a report's marker against this host." },
        ],
        lesson: "Start from the question and the plugin follows. Each one reads a structure that lives in RAM, which is why a disk image cannot stand in for it.",
      },
      {
        kind: "sort",
        title: "Which Image Holds It?",
        prompt: "The director asks whether the Trust can skip one image to save time. Sort each item by where you could recover it, on a machine that was running at capture and had rebooted last week.",
        buckets: [
          { id: "mem", label: "Memory image only" },
          { id: "disk", label: "Disk image only" },
          { id: "both", label: "Both" },
        ],
        items: [
          { id: "shell", text: "Shellcode injected into explorer.exe, with no file behind it", bucket: "mem", why: "No file was ever written, so disk has nothing. It exists only as bytes in that process's memory." },
          { id: "unpacked", text: "The list of file extensions a packed loader will steal, stored encrypted in its .exe", bucket: "mem", why: "On disk the list is ciphertext. The loader must decrypt it to use it, so the plaintext is in RAM while it runs." },
          { id: "archive", text: "The password typed on a running archiver's command line, with no process logging on the host", bucket: "mem", why: "With no logging it was never written anywhere. It sits in the process's arguments until the process ends." },
          { id: "unlinked", text: "A process a rootkit removed from the OS list, so windows.pslist no longer shows it", bucket: "mem", why: "The process object is still in RAM for a signature search to find, and being hidden leaves no file behind." },
          { id: "tuesday", text: "Which programs ran last Tuesday, before the reboot", bucket: "disk", why: "Memory is one instant. Prefetch, the $MFT and the journal persist across reboots and hold history." },
          { id: "cipher", text: "The encrypted .exe itself, as it sits on the volume, ready to hash", bucket: "disk", why: "RAM holds the unpacked, running form, which hashes differently. The file as delivered is on disk." },
          { id: "service", text: "The name and path of a normal running service", bucket: "both", why: "It runs from a file, so the file is on disk and the process, with its image path, is in RAM." },
          { id: "reg", text: "A registry value the running system has loaded", bucket: "both", why: "Hives live on disk and are cached in RAM. Memory may even hold a change not yet flushed to the hive file." },
        ],
      },
    ],

    // ── Reading 3: hashing and custody on a running host ──
    "mdf-r3": [
      {
        kind: "hotspot",
        title: "Find the Holes in a Custody Record",
        prompt: "Before Yusra's image goes to the insurer's lawyers, Yusra pulls the record from a contractor's job on the collections server last year as a warning. Click every line that would not survive a sceptical reviewer.",
        artifact: "Evidence custody record · HMT-COLL-01 · live collection",
        finish: "That record would have been taken apart in review. Every line you found could have been written correctly on the day, and none can be fixed afterwards.",
        primer: {
          title: "What a hash proves on a running host",
          points: [
            "Hash the file the moment it finishes writing, before copying, renaming or opening it. That SHA256 is the baseline every later copy is checked against.",
            "A SHA256 fingerprints the bytes of **one file**. A running machine has moved on by the time that fingerprint exists, so record when the snapshot was taken too.",
            "Write blockers belong to dead-box work, on a drive that is powered off. A running OS writes where it likes, so a live record names your own actions and what was outside your control.",
            "A live record adds to the usual form: tool and version, exact command, analyst, start and end time, SHA256, **and** what else was running or touched during collection, such as an antivirus scan or a killed process.",
            "Evidence moves straight to access-controlled or write-once storage, and each later opening is logged like the original collection.",
          ],
          example: {
            label: "Clean lines, from a kiosk record",
            lines: [
              "`2026-05-12 14:31:08 UTC` dump finished. `14:31:40` SHA256 recorded on the collection drive.",
              "During collection: endpoint scan running, not stopped. No process killed.",
              "Limitation: collected live, so the dump is one moment of a changing system.",
            ],
          },
          fold: true,
        },
        parts: [
          { id: "item", text: "Item: memory dump, HMT-COLL-01. Server could not be stopped during business hours.", flag: false, note: "A clear reason for a live collection. Stating it up front is exactly right.", style: "meta" },
          { id: "tool", text: "Tool: winpmem 4.0.rc1, run from read-only USB. Command: winpmem_mini_x64.exe F:\\COLL01.raw", flag: false, note: "Tool, version and exact command line: all present.", style: "meta" },
          { id: "who", text: "Analyst: see ticket", flag: true, note: "The record itself must name the analyst. A pointer to a ticket someone can edit or close is not a custody statement.", style: "body" },
          { id: "time", text: "Collected: Tuesday afternoon", flag: true, note: "A record needs exact start and end timestamps. The dump is a snapshot of one moment, so its time is part of the evidence.", style: "body" },
          { id: "blocker", text: "Hardware write blocker fitted to the server's system disk during the dump", flag: true, note: "That hardware sits on a drive that is switched off. This server was up and using its disk, so the line claims a guarantee that never existed.", style: "body" },
          { id: "hash", text: "SHA256 calculated next morning, on the analyst's laptop", flag: true, note: "The baseline belongs on the original, the moment it finishes writing. A hash taken hours later, elsewhere, leaves a gap nobody can account for.", style: "body" },
          { id: "claim", text: "Integrity: SHA256 shows the server was clean at handover", flag: true, note: "A hash describes the bytes of one file. It says nothing about the health of the server, then or later.", style: "body" },
          { id: "other", text: "Other activity during collection: none recorded", flag: true, note: "On a live server something was running: scans, backups, the database itself. Blank is not the same as none, and a reviewer will ask.", style: "body" },
          { id: "store", text: "Stored: \\\\HMT-FS-02\\IT\\temp, default permissions", flag: true, note: "Evidence belongs on access-controlled storage with access logged, not on a shared folder anyone can open.", style: "body" },
          { id: "log", text: "Access log: three names, each with date, time and reason", flag: false, note: "Correct. Everyone who opens the file later is an access event in the chain of custody.", style: "body" },
        ],
      },
    ],

    // ── Reading 4: the signature, memory beside disk ──
    "mdf-r4": [
      {
        kind: "trace",
        title: "Two Timelines: Read Memory Beside Disk",
        prompt: "Yusra has the memory image on one screen and the parsed disk artefacts on the other. Read them side by side: the running process, the same file on disk, the same record in RAM, then the journal. Click the row that answers each step.",
        lead: "Image of HMT-REG-07, taken 2026-10-29 14:21 UTC. A process is running from C:\\ProgramData\\CatalogueLink, a folder the registrar says nobody has touched in years.",
        primer: {
          title: "Two clocks in one MFT record",
          points: [
            "Each file's **$MFT** (Master File Table) record holds two sets of MACB times: Modified, Accessed, Changed (the record), Born. **$STANDARD_INFORMATION** ($SI) is what Explorer, `dir` and Get-Item show. **$FILE_NAME** ($FN) is normally set only on creation, rename or move.",
            "Common timestomping tools (ATT&CK T1070.006) rewrite $SI only, because forging $FN takes direct MFT editing. So a $SI Created far older than $FN Created is one of the strongest single signs.",
            "Parsers print the attribute type: in MFTECmd, `Created0x10` is $SI and `Created0x30` is $FN. Its `SI<FN` and `uSecZeros` columns flag candidates, not verdicts.",
            "**$UsnJrnl** (the USN Change Journal) is a running log of changes with a reason code each, not a snapshot. MFTECmd prints `FileCreate`, `DataExtend`, `RenameNewName`, `BasicInfoChange`. That last one, BASIC_INFO_CHANGE in Windows' own naming, covers edits to a file's metadata block: its attribute flags or its MACB values.",
            "`EntryNumber` stays with a record through a rename, so it joins the old name to the new one.",
          ],
          example: {
            label: "The method, on a conservator's scan",
            lines: [
              "`scan_0412.tif` Created0x10 `2026-04-12 10:02:11.5523910`, Created0x30 `2026-04-12 10:02:11.5523910`. Same instant, real fraction: the clocks agree.",
              "LastModified0x10 `2024-01-08 16:30:44.1180000` is older than Created. Normal: a copy keeps the source's Modified and gets a fresh Created.",
              "So compare Created with Created. A Modified older than Created is not a forgery by itself.",
            ],
          },
          fold: true,
        },
        steps: [
          {
            id: "proc",
            ask: "clsvc.exe is the real CatalogueLink service, and its parent is services.exe (PID 972). Which process has a CatalogueLink-style name but a different parent?",
            source: "MEMORY · windows.pslist · HMT-REG-07",
            columns: ["PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime"],
            rows: [
              ["4", "0", "System", "0xc58b6f2a1040", "164", "-", "N/A", "False", "2026-10-28 07:51:02 UTC", "N/A"],
              ["860", "744", "wininit.exe", "0xc58b70e4e080", "3", "-", "0", "False", "2026-10-28 07:51:09 UTC", "N/A"],
              ["972", "860", "services.exe", "0xc58b70f12140", "9", "-", "0", "False", "2026-10-28 07:51:10 UTC", "N/A"],
              ["1712", "972", "svchost.exe", "0xc58b71a3d300", "31", "-", "0", "False", "2026-10-28 07:51:13 UTC", "N/A"],
              ["3204", "972", "clsvc.exe", "0xc58b72c08240", "6", "-", "0", "True", "2026-10-28 07:51:41 UTC", "N/A"],
              ["6648", "1712", "clsync32.exe", "0xc58b73e91080", "4", "-", "0", "True", "2026-10-28 07:52:14 UTC", "N/A"],
              ["7240", "7184", "explorer.exe", "0xc58b74102080", "58", "-", "1", "False", "2026-10-28 08:02:37 UTC", "N/A"],
            ],
            answer: 5,
            why: "clsync32.exe, PID 6648, has PPID 1712: a svchost.exe, the pattern of a scheduled task, not services.exe. On its own that is only a question. What the file says about itself is next.",
            learned: "clsync32.exe, PID 6648, started 2026-10-28 07:52:14 under svchost.exe PID 1712.",
          },
          {
            id: "mft",
            ask: "Part of the same folder, from the disk image. Which file's two Created clocks disagree?",
            source: "DISK · $MFT · MFTECmd, ParentPath .\\ProgramData\\CatalogueLink, excerpt",
            columns: ["EntryNumber", "FileName", "Created0x10", "Created0x30", "LastModified0x10"],
            rows: [
              ["247906", "clsvc.exe", "2017-05-22 09:14:33.2081440", "2017-05-22 09:14:33.2081440", "2016-11-30 17:02:18.0000000"],
              ["247911", "clcat.dll", "2017-05-22 09:14:34.6102950", "2017-05-22 09:14:34.6102950", "2016-11-30 17:02:20.0000000"],
              ["247914", "readme.txt", "2017-05-22 09:14:35.0930126", "2017-05-22 09:14:35.0930126", "2016-10-03 11:20:44.0000000"],
              ["248113", "clsync32.exe", "2017-05-22 09:14:00.0000000", "2026-10-27 23:41:07.4412083", "2017-05-22 09:14:00.0000000"],
              ["247920", "catalogue.ini", "2017-05-22 09:15:02.7741006", "2017-05-22 09:15:02.7741006", "2026-10-26 16:40:12.3380915"],
            ],
            answer: 3,
            why: "clsync32.exe: Created0x10 ($SI) sits right beside its neighbours, in 2017 with a fraction of all zeros, while Created0x30 ($FN) says last Tuesday night. clsvc.exe's older Modified is an installer keeping a build date, and catalogue.ini's newer Modified is someone saving a settings file. Neither is a Created disagreement.",
            learned: "$MFT entry 248113: $SI says 2017-05-22, $FN says 2026-10-27 23:41:07.",
          },
          {
            id: "ram",
            ask: "RAM caches MFT records too, and Volatility can read them without touching the disk image. Which row holds this record's true creation time?",
            source: "MEMORY · windows.mftscan.MFTScan",
            columns: ["Record Number", "Attribute Type", "Created", "Modified", "Filename"],
            rows: [
              ["247906", "STANDARD_INFORMATION", "2017-05-22 09:14:33 UTC", "2016-11-30 17:02:18 UTC", "N/A"],
              ["247906", "FILE_NAME", "2017-05-22 09:14:33 UTC", "2017-05-22 09:14:33 UTC", "clsvc.exe"],
              ["248113", "STANDARD_INFORMATION", "2017-05-22 09:14:00 UTC", "2017-05-22 09:14:00 UTC", "N/A"],
              ["248113", "FILE_NAME", "2026-10-27 23:41:07 UTC", "2026-10-27 23:41:07 UTC", "clsync32.exe"],
            ],
            answer: 3,
            why: "The 2026 date sits in the FILE_NAME row, in line with the $MFT. Memory and disk now show the same disagreement from two separate sources, so a parser fault is off the table.",
            learned: "Memory agrees with disk: $FN holds the real birth, $SI holds the forged date.",
          },
          {
            id: "usn",
            ask: "The journal keeps the sequence the $MFT cannot. Which entry is the first moment this file's timestamps were changed?",
            source: "DISK · $UsnJrnl:$J · MFTECmd",
            columns: ["UpdateTimestamp", "Name", "EntryNumber", "UpdateReasons"],
            rows: [
              ["2026-10-27 23:41:07.4412083", "tmp4F2A.tmp", "248113", "FileCreate"],
              ["2026-10-27 23:41:07.4431190", "tmp4F2A.tmp", "248113", "DataExtend|FileCreate"],
              ["2026-10-27 23:41:09.1180255", "tmp4F2A.tmp", "248113", "DataExtend|FileCreate|Close"],
              ["2026-10-27 23:43:30.6021874", "tmp4F2A.tmp", "248113", "RenameOldName"],
              ["2026-10-27 23:43:30.6022010", "clsync32.exe", "248113", "RenameNewName"],
              ["2026-10-27 23:43:30.6024551", "clsync32.exe", "248113", "RenameNewName|Close"],
              ["2026-10-27 23:44:52.3307716", "clsync32.exe", "248113", "BasicInfoChange"],
              ["2026-10-27 23:44:52.3309002", "clsync32.exe", "248113", "BasicInfoChange|Close"],
            ],
            answer: 6,
            why: "This is the first row carrying that reason, at 23:44:52. Carry that time into the next lab. EntryNumber 248113 also shows tmp4F2A.tmp and clsync32.exe are one record.",
            learned: "Born as tmp4F2A.tmp at 23:41:07, renamed 23:43:30, timestamps changed 23:44:52.",
          },
        ],
      },
      {
        kind: "trace",
        title: "Three More Witnesses: Prefetch, ShimCache, Amcache",
        prompt: "The $MFT and the journal have spoken, but Yusra never signs off on one artefact family. Bring in the execution artefacts, go back to memory, then strike the bad row from the timeline. Two of these sources are easy to misread.",
        lead: "clsync32.exe, $MFT entry 248113. Real birth 2026-10-27 23:41:07, timestamps changed 23:44:52. Did it run, when, and what was it doing at capture?",
        primer: {
          title: "What each artefact really records",
          points: [
            "**Prefetch** (`C:\\Windows\\Prefetch\\NAME.EXE-HASH.pf`) is written when a program runs: a run count and up to eight run times. PECmd parses it. Windows Server has it off by default, so an empty folder there proves nothing.",
            "**ShimCache** (AppCompatCache, in the SYSTEM hive) stores a path and that file's **$SI Last Modified as it stood at that moment**. That is not a run time. Windows holds it in RAM and writes it to the hive at shutdown. On Windows 10 and 11 `Executed` is a flag that suggests a run but does not prove one.",
            "**Amcache.hve** records files the system has seen: SHA1, the entry's last write time, and `LinkDate`, the compile time from the PE header. A file cannot predate its compile time, though an attacker can forge that too.",
            "**$LogFile** is NTFS's transaction journal: lower-level metadata operations, harder to edit selectively than one MACB field. Use it when a $UsnJrnl or $MFT time is in doubt.",
            "Each source can mislead alone. A defensible timeline is built where independent sources agree, and flags where they do not.",
          ],
          example: {
            label: "The method, on a label printer's driver",
            lines: [
              "ShimCache: `C:\\Tools\\lblprint.exe`, LastModifiedTimeUTC `2023-02-14 08:31:10`.",
              "Wrong read: it ran in 2023. Right read: in 2023 its content last changed, and it was cached some time after.",
              "Prefetch: `LBLPRINT.EXE-5C1D7A02.pf`, RunCount 14, LastRun `2026-09-30 10:12:41`. That is a run time.",
            ],
          },
          fold: true,
        },
        steps: [
          {
            id: "pf",
            ask: "Did the file run before the morning reboot? Find the row that shows it.",
            source: "DISK · Prefetch · PECmd",
            columns: ["SourceFilename", "ExecutableName", "RunCount", "LastRun", "PreviousRun0"],
            rows: [
              ["CLSYNC32.EXE-2D90B1F4.pf", "CLSYNC32.EXE", "2", "2026-10-28 07:52:14", "2026-10-27 23:43:41"],
              ["CLSVC.EXE-7A31C0E2.pf", "CLSVC.EXE", "212", "2026-10-28 07:51:41", "2026-10-27 07:50:58"],
              ["CLUPDATE.EXE-E40B6A17.pf", "CLUPDATE.EXE", "19", "2026-09-02 08:15:03", "2026-06-03 08:14:51"],
              ["NOTEPAD.EXE-D8414F97.pf", "NOTEPAD.EXE", "31", "2026-10-26 16:39:58", "2026-10-21 11:02:40"],
            ],
            answer: 0,
            why: "RunCount 2, with runs at 23:43:41 and 07:52:14. The service beside it has 212 runs. The first run came 71 seconds before the timestamps changed, so whoever dropped it tested it, then dressed it up.",
            learned: "Ran twice: 2026-10-27 23:43:41 and 2026-10-28 07:52:14.",
          },
          {
            id: "shim",
            ask: "The $MFT now says this file's $SI Last Modified is 2017. Which cached entry remembers a different value for the same path?",
            source: "DISK · ShimCache · AppCompatCacheParser, SYSTEM hive, excerpt",
            columns: ["CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed"],
            rows: [
              ["0", "C:\\Windows\\System32\\SearchProtocolHost.exe", "2026-09-16 04:12:33", "Yes"],
              ["1", "C:\\Windows\\System32\\cmd.exe", "2026-09-16 04:12:29", "Yes"],
              ["2", "C:\\ProgramData\\CatalogueLink\\clsync32.exe", "2026-10-27 23:41:09", "Yes"],
              ["3", "C:\\ProgramData\\CatalogueLink\\clsvc.exe", "2016-11-30 17:02:18", "Yes"],
              ["4", "C:\\ProgramData\\CatalogueLink\\cluninst.exe", "2016-11-30 17:02:21", "No"],
            ],
            answer: 2,
            why: "ShimCache copied the $SI Last Modified as it stood at 23:43:41, before the change at 23:44:52, so it still shows 23:41:09, when the data finished writing. Not a run time: a frozen copy of a field that was overwritten afterwards. Executed Yes fits the Prefetch run, but the flag alone would only suggest one.",
            learned: "ShimCache kept the pre-change Modified time: 2026-10-27 23:41:09.",
          },
          {
            id: "amcache",
            ask: "A file cannot be older than the build that produced it. Which row's compile time rules out a 2017 birth?",
            source: "DISK · Amcache.hve · AmcacheParser, UnassociatedFileEntries",
            columns: ["Name", "FileKeyLastWriteTimestamp", "LinkDate", "Size", "SHA1"],
            rows: [
              ["clsvc.exe", "2025-02-11 03:14:20", "2016-11-30 17:01:54", "1482752", "6be1c0d7..."],
              ["clupdate.exe", "2025-02-11 03:14:21", "2017-03-02 12:44:10", "530432", "a17f92ce..."],
              ["msedgewebview2.exe", "2026-10-14 03:12:09", "2026-10-07 21:18:36", "3417600", "c2d4e8a1..."],
              ["clsync32.exe", "2026-10-28 03:12:44", "2026-10-19 06:33:51", "287744", "3f9ac41e..."],
            ],
            answer: 3,
            why: "LinkDate 2026-10-19 on a file claiming 2017. The browser component's recent LinkDate is fine, because it claims nothing older. Amcache also gives you the SHA1 to pivot on across the Trust. LinkDate can be forged, so it supports the timeline without standing alone.",
            learned: "Compiled 2026-10-19, eight days before it arrived. SHA1 recorded for a fleet search.",
          },
          {
            id: "net",
            ask: "Disk says when it arrived and ran. Only memory says what it was doing at capture. Which socket belonged to PID 6648?",
            source: "MEMORY · windows.netscan",
            columns: ["Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"],
            rows: [
              ["0xc58b75a1e3a0", "TCPv4", "192.168.40.27", "49821", "192.168.40.10", "445", "ESTABLISHED", "4", "System", "2026-10-29 08:04:11 UTC"],
              ["0xc58b75c04910", "TCPv4", "192.168.40.27", "50217", "203.0.113.77", "443", "ESTABLISHED", "6648", "clsync32.exe", "2026-10-29 14:18:52 UTC"],
              ["0xc58b75d2f010", "TCPv4", "192.168.40.27", "50198", "198.51.100.24", "443", "ESTABLISHED", "9120", "msedge.exe", "2026-10-29 14:02:37 UTC"],
              ["0xc58b75e7b6c0", "TCPv4", "192.168.40.27", "49744", "192.168.40.5", "135", "CLOSE_WAIT", "1712", "svchost.exe", "2026-10-29 07:58:20 UTC"],
            ],
            answer: 1,
            why: "A session to 203.0.113.77:443, opened three minutes before capture, with the owner named in the row. No disk artefact produced this. It is the one fact in this case that only the memory timeline could give you.",
            learned: "At capture, PID 6648 held a session to 203.0.113.77:443.",
          },
          {
            id: "merged",
            ask: "Yusra's draft merged timeline for the case file. One row does not belong in it as a fact. Which do you strike?",
            source: "MERGED · draft timeline, clsync32.exe",
            columns: ["Time (UTC)", "Source", "Event"],
            rows: [
              ["2026-10-19 06:33:51", "Amcache LinkDate", "Compiled, per PE header"],
              ["2026-10-27 23:41:07", "$UsnJrnl, $FN", "Created as tmp4F2A.tmp"],
              ["2026-10-27 23:43:41", "Prefetch", "First run"],
              ["2026-10-27 23:44:52", "$UsnJrnl", "BasicInfoChange"],
              ["2017-05-22 09:14:00", "$MFT $SI", "File created"],
              ["2026-10-28 07:52:14", "Prefetch, windows.pslist", "Second run, PID 6648"],
              ["2026-10-29 14:18:52", "windows.netscan", "Session to 203.0.113.77:443"],
            ],
            answer: 4,
            why: "That row's only source is the attribute this case has shown was rewritten, and every other source contradicts it. A timeline built from $SI alone inherits the forgery with no way to flag it. Keep the value in the notes as a forged date, not as an event.",
            learned: "Defensible timeline: 19 October build, 27 October arrival, no 2017 event.",
          },
        ],
      },
    ],

    // ── Task la1 warm-up: gap alone is not proof ──
    "mdf-la1": [
      {
        kind: "tune",
        title: "Tune a Sweep Across Every $MFT",
        prompt: "Yusra wants this check across every server's $MFT, but the Trust's migration left thousands of files with old dates. Your rule fires when $SI Created is older than $FN Created by at least N days, and the $SI fraction of a second ends in at least M zeros. The test set has 5 confirmed cases: catch at least 4 with no more than 1 false alarm.",
        eventColumn: "file and what the $MFT shows",
        primer: {
          title: "Why an old date alone proves nothing",
          points: [
            "NTFS keeps times to 100 nanoseconds, seven decimal digits. Real activity fills them. A tool that sets a typed-in date leaves `.0000000`.",
            "A **restore or migration tool that keeps dates** (robocopy does) writes the old Created into $SI while $FN records the day it landed. Same gap, innocent cause, and the real fraction survives.",
            "Coarse clocks make innocent zeros: FAT32 media stores whole seconds, and some sync tools keep only milliseconds, which is four trailing zeros.",
            "Careful attackers back-date by days, or copy a neighbour's times, fraction included. A sweep **ranks** files for review. The journal and the other sources decide.",
          ],
          example: {
            label: "The method, on a gift shop spreadsheet",
            lines: [
              "`giftshop_2024.xlsx`: $SI Created `2024-03-02 11:20:41.6631407`, $FN Created `2026-01-15 19:03:12.2205518`.",
              "Gap 684 days, no trailing zeros, and $UsnJrnl shows thousands of neighbours landing in the same minute.",
              "A migration, not a forgery. The fraction and the crowd both say so.",
            ],
          },
          fold: true,
        },
        dials: [
          { id: "gap", label: "$SI Created older than $FN Created, by at least", short: "days", unit: "d", min: 0, max: 120, step: 1, start: 0 },
          { id: "zeros", label: "Trailing zeros in the $SI fraction, at least", short: "zeros", min: 0, max: 7, step: 1, start: 0 },
        ],
        events: [
          { id: "s1", label: "svcupd.exe in ProgramData: 3,290 days gap, fraction .0000000", bad: true, values: { gap: 3290, zeros: 7 } },
          { id: "s2", label: "wshelper.dll in System32: 41 days gap, fraction .0000000", bad: true, values: { gap: 41, zeros: 7 } },
          { id: "s3", label: "rpt_tool.exe, dated to last patch night: 12 days gap, fraction .0000000", bad: true, values: { gap: 12, zeros: 7 } },
          { id: "s4", label: "tasksync.exe in a vendor folder: 2,104 days gap, fraction .0000000", bad: true, values: { gap: 2104, zeros: 7 } },
          { id: "s5", label: "msvcsvc.dll, times copied from a Windows DLL: 905 days gap, fraction .3184620", bad: true, values: { gap: 905, zeros: 1 } },
          { id: "n1", label: "Accession photo moved by the migration tool: 1,460 days gap, fraction .7741390", bad: false, values: { gap: 1460, zeros: 1 } },
          { id: "n2", label: "Loan contract restored from backup: 6 days gap, fraction .8812337", bad: false, values: { gap: 6, zeros: 0 } },
          { id: "n3", label: "Photo from a FAT32 scanner card, dates kept: 9 days gap, fraction .0000000", bad: false, values: { gap: 9, zeros: 7 } },
          { id: "n4", label: "Sync client with millisecond times: 400 days gap, fraction .5120000", bad: false, values: { gap: 400, zeros: 4 } },
          { id: "n5", label: "Vendor installer stamped with its release date: 220 days gap, fraction .0000000", bad: false, values: { gap: 220, zeros: 7 } },
          { id: "n6", label: "Word template, ordinary save: no gap, fraction .2291046", bad: false, values: { gap: 0, zeros: 0 } },
          { id: "n7", label: "Log archive unzipped with dates kept: 3 days gap, fraction .0000000", bad: false, values: { gap: 3, zeros: 7 } },
        ],
        goal: { catch: 4, maxFalse: 1 },
        lesson: "Gap plus a round fraction is a strong filter, not a verdict. It cannot separate a vendor's stamped date from a forgery, and it missed the DLL whose times were copied with their fraction. Both get settled the same way: read the $UsnJrnl for that entry and ask which source has no reason to lie.",
      },
    ],

    // ── Task f1 warm-up: reading a gap out of the journal ──
    "mdf-f1": [
      {
        kind: "worksheet",
        title: "Time a Gap From the Journal",
        prompt: "Yusra found two more files from the same intruder. For each, work out how long it kept its true timestamps: from the real creation to the first time NTFS recorded a change to them. Ignore the entries in between.",
        caption: "$UsnJrnl:$J · MFTECmd · HMT-REG-07, excerpt",
        columns: ["UpdateTimestamp", "Name", "EntryNumber", "UpdateReasons"],
        rows: [
          ["2026-10-27 23:52:48", "clhelper.dll", "248131", "FileCreate"],
          ["2026-10-27 23:52:49", "clhelper.dll", "248131", "DataExtend|FileCreate|Close"],
          ["2026-10-27 23:53:20", "clhelper.dll", "248131", "SecurityChange"],
          ["2026-10-27 23:54:03", "clhelper.dll", "248131", "BasicInfoChange"],
          ["2026-10-27 23:54:03", "clhelper.dll", "248131", "BasicInfoChange|Close"],
          ["2026-10-27 23:59:40", "clcfg.bin", "248140", "FileCreate"],
          ["2026-10-27 23:59:41", "clcfg.bin", "248140", "DataExtend|FileCreate|Close"],
          ["2026-10-28 00:01:15", "clcfg.bin", "248140", "BasicInfoChange"],
          ["2026-10-28 00:01:15", "clcfg.bin", "248140", "BasicInfoChange|Close"],
        ],
        questions: [
          { id: "a", q: "clhelper.dll: how many seconds from FileCreate to the first BasicInfoChange?", hint: "SecurityChange is not a timestamp change. Take the two rows and subtract.", answer: ["75", "75 seconds"], why: "23:52:48 to 23:54:03 is 1 minute 15 seconds, so 75. The SecurityChange row is a permissions change, a distractor. A gap this short suggests a hands-on or scripted step." },
          { id: "b", q: "clcfg.bin: how many seconds from FileCreate to the first BasicInfoChange?", hint: "The date rolls over between the two rows.", answer: ["95", "95 seconds"], why: "20 seconds to midnight, then 1 minute 15 seconds after it: 20 + 75 = 95. Watch the date column: a subtraction on the time alone gives nonsense." },
        ],
      },
    ],

    // ── Reading 5: an eraser writes somewhere else ──
    "mdf-r5": [
      {
        kind: "trace",
        title: "Follow an Eraser Across Sources",
        prompt: "Friday morning. The perimeter firewall has flagged a large upload from HMT-FS-02 in the 02:00 window, so Yusra asks what ran on that server at the time. Start with the server's own logs, then follow where they lead.",
        lead: "HMT-FS-02, file server. Firewall alert: large outbound upload, around 02:10 on 30 October.",
        primer: {
          title: "Clearing a log writes a log",
          points: [
            "**Event ID 1102** in the Security log means the audit log was cleared, with the account and time. Any other channel cleared raises **Event ID 104** in the System log, naming that channel.",
            "A clear reaches only the channels it names, on that host. For every other source, ask two things: where is it stored, and what kind of thing does it record?",
            "`wevtutil` works on event channels. The NTFS journals are not event channels.",
            "Process-creation telemetry (Sysmon Event ID 1, or EDR) gives image, command line, parent and account. Shadow copy deletion (T1490) destroys the copies, but vssadmin, `wmic shadowcopy delete` or the PowerShell equivalent all show up here.",
            "The pattern: an eraser attacks one source and writes to another. An empty source is a timestamp to pivot from, never a dead end.",
          ],
          example: {
            label: "The method, on another server",
            lines: [
              "A 104 says `Application` was cleared at 09:12. Set the window: 09:00 to 09:20.",
              "Ask each remaining source for that window: off-host telemetry, the firewall, the journal.",
              "Note what you cannot reach, so the gap is stated and not hidden.",
            ],
          },
          fold: true,
        },
        steps: [
          {
            id: "sys",
            ask: "The log starts at 02:14, after the upload. Which row shows the host's PowerShell history went as well?",
            source: "System log · HMT-FS-02",
            columns: ["TimeCreated", "Id", "ProviderName", "Message"],
            rows: [
              ["2026-10-30 02:14:06", "104", "Microsoft-Windows-Eventlog", "The System log file was cleared."],
              ["2026-10-30 02:14:07", "104", "Microsoft-Windows-Eventlog", "The Application log file was cleared."],
              ["2026-10-30 02:14:07", "104", "Microsoft-Windows-Eventlog", "The Microsoft-Windows-PowerShell/Operational log file was cleared."],
              ["2026-10-30 02:15:33", "7036", "Service Control Manager", "The Background Intelligent Transfer Service service entered the running state."],
              ["2026-10-30 03:00:02", "7036", "Service Control Manager", "The Windows Update service entered the running state."],
            ],
            answer: 2,
            why: "Each 104 names the channel it records, so this row names the PowerShell log. The clear is itself evidence: it gives you a precise time to search around in whatever the intruder could not reach.",
            learned: "Logs cleared 02:14:06 to 02:14:07, PowerShell's included. Window starts here.",
          },
          {
            id: "edr",
            ask: "The clear was not the first move. Which command removed this server's restore points?",
            source: "EDR console, stored off the host · process events, 02:00 to 02:20",
            columns: ["Time", "Account", "ParentProcess", "Process", "CommandLine"],
            rows: [
              ["02:03:11", "NT AUTHORITY\\SYSTEM", "services.exe", "svchost.exe", "svchost.exe -k netsvcs -p -s wuauserv"],
              ["02:11:48", "HARROWGATE\\adm.thorne", "wsmprovhost.exe", "cmd.exe", "cmd.exe /c whoami"],
              ["02:12:02", "HARROWGATE\\adm.thorne", "cmd.exe", "vssadmin.exe", "vssadmin list shadows"],
              ["02:12:40", "HARROWGATE\\adm.thorne", "cmd.exe", "wmic.exe", "wmic shadowcopy delete /nointeractive"],
              ["02:14:05", "HARROWGATE\\adm.thorne", "cmd.exe", "wevtutil.exe", "wevtutil cl System"],
              ["02:14:06", "HARROWGATE\\adm.thorne", "cmd.exe", "wevtutil.exe", "wevtutil cl Application"],
              ["02:14:07", "HARROWGATE\\adm.thorne", "cmd.exe", "wevtutil.exe", "wevtutil cl Microsoft-Windows-PowerShell/Operational"],
            ],
            answer: 3,
            why: "wmic shadowcopy delete. The vssadmin line above it only lists, a read-only look around first. The copies themselves are gone for good, but the act is here with account, parent and command line, because this telemetry left the host before the clear ran. Destroying restore points is a classic step before encryption.",
            learned: "adm.thorne deleted shadow copies at 02:12:40, then cleared logs.",
          },
          {
            id: "usn",
            ask: "A tool was dropped and removed in the same window. It is no longer on disk. Which row fixes when it left?",
            source: "$UsnJrnl:$J · HMT-FS-02 · MFTECmd",
            columns: ["UpdateTimestamp", "Name", "EntryNumber", "UpdateReasons"],
            rows: [
              ["2026-10-30 02:09:51", "fsops.exe", "91344", "FileCreate"],
              ["2026-10-30 02:09:52", "fsops.exe", "91344", "DataExtend|FileCreate|Close"],
              ["2026-10-30 02:13:20", "fsops.exe", "91344", "BasicInfoChange|Close"],
              ["2026-10-30 02:14:31", "fsops.exe", "91344", "FileDelete|Close"],
              ["2026-10-30 02:15:02", "wu_cache.tmp", "91390", "FileCreate"],
            ],
            answer: 3,
            why: "FileDelete|Close at 02:14:31, after the clear. This entry can outlive both the file and its $MFT record. It gives the tool's name and its life on this volume, and the EDR rows give what was typed.",
            learned: "fsops.exe lived on HMT-FS-02 from 02:09:51 to 02:14:31.",
          },
          {
            id: "fw",
            ask: "The same far end as HMT-REG-07's socket would tie both hosts to one operator. Which row shows it?",
            source: "Perimeter firewall · traffic log, 02:00 to 02:20",
            columns: ["time", "srcip", "dstip", "dstport", "action", "sentbyte"],
            rows: [
              ["02:04:18", "192.168.40.10", "198.51.100.24", "443", "accept", "48211"],
              ["02:07:55", "192.168.40.5", "198.51.100.61", "123", "accept", "152"],
              ["02:10:03", "192.168.40.10", "203.0.113.77", "443", "accept", "19083344"],
              ["02:16:40", "192.168.40.31", "203.0.113.190", "443", "deny", "0"],
            ],
            answer: 2,
            why: "HMT-FS-02 (192.168.40.10) sent 19 MB to 203.0.113.77, the address clsync32.exe held in memory. The firewall stores its own log, so nothing on the server could clear it. Two hosts, one operator, and data left the building.",
            learned: "HMT-FS-02 sent 19 MB to 203.0.113.77 at 02:10:03. Same operator as HMT-REG-07.",
          },
        ],
      },
      {
        kind: "codebreak",
        title: "What Did the Eraser Miss?",
        prompt: "The intruder used more than one clean-up tool. Yusra reads each one as a clue: what did it fail to reach? Name the artefact, without any $ sign.",
        primer: {
          title: "Three more erasers",
          points: [
            "Deleting Prefetch files removes the run counts, and only those. The deletions themselves are file changes, and the other execution artefacts live elsewhere.",
            "**SDelete** overwrites a file's data and renames it through the alphabet before deleting it, so a journal shows names like `AAAAAA.AAA`, `BBBBBB.BBB`. The data is gone. The name history is not.",
            "`fsutil usn deletejournal /d C:` removes the change journal. Its own launch is a process event, and it does not reach NTFS's transaction journal, which is small and circular but separate.",
          ],
          example: {
            label: "The method, on an emptied Recycle Bin",
            lines: [
              "Eraser: the Recycle Bin was emptied, so the files are gone from view.",
              "Ask: which source records file changes and sits outside the Bin? The change journal.",
              "So the eraser removed the file and left its deletion on record elsewhere.",
            ],
          },
          fold: true,
        },
        rounds: [
          { id: "pf", clue: "del C:\\Windows\\Prefetch\\*.pf emptied the folder. Each deletion is still on record with a reason code in which NTFS log?", answer: "USNJRNL", why: "Each .pf deletion is a file-system change, so $UsnJrnl records it with FileDelete. The eraser leaves a list of the very programs it was trying to hide." },
          { id: "shim", clue: "Same clean-up. Which cache, written to the SYSTEM hive at shutdown, may still hold the tool's path?", answer: "SHIMCACHE", why: "ShimCache lives in the registry, not the Prefetch folder, so deleting .pf files does nothing to it. Remember it shows a path and a Modified time, not a run time." },
          { id: "am", clue: "SDelete destroyed a tool's data. Which hive file can still hold that tool's SHA1 and compile time?", answer: "AMCACHE", why: "Amcache.hve recorded the file when the system saw it. With the data overwritten, that SHA1 may be the only way left to identify the tool or search other hosts for it." },
          { id: "lf", clue: "fsutil usn deletejournal /d C: removed the change journal. Which lower-level NTFS transaction journal does it leave in place?", answer: "LOGFILE", why: "$LogFile is separate from $UsnJrnl and exists for crash recovery. It wraps quickly, so it holds only recent operations, but this eraser does not touch it. The fsutil launch is also a process event." },
        ],
        lesson: "Every eraser is narrow. It removes one source, and the removal is an event that lands in another. Ask what it could not reach.",
      },
    ],

    // ── Reading 6: preserve or contain ──
    "mdf-r6": [
      {
        kind: "defuse",
        title: "Contain or Preserve? Four Live Calls",
        prompt: "Harrowgate's worst Friday. HMT-CON-03, a conservation lab workstation with no EDR agent, has joined the case. Each card is a separate call with its own facts. Read what is happening right now and cut the wire that fits.",
        device: "Incident bridge · Harrowgate Museum Trust",
        seconds: 100,
        primer: {
          title: "Three questions before you touch anything",
          points: [
            "**Know the price.** Power-off stops everything and wipes RAM in that moment. Cutting the network silences a beacon, so you lose sight of where it would go next.",
            "**Is data being destroyed or sent out right now?** Active encryption or a large running transfer usually justifies containing at once, even at a real cost to evidence.",
            "**Is the scope known?** If other hosts may be involved, containing one can tip off a watching attacker. With nothing burning, scope comes first.",
            "**What do the plan and the law require?** Evidence duties for a likely legal or regulatory matter are set in advance, and big calls go to the incident commander, not whoever is on shift.",
          ],
          example: {
            label: "The method, on a ticket-office PC",
            lines: [
              "State: a ticket-office PC needs containing. One low-impact host, and the playbook names it.",
              "Question: whose decision is this? The playbook gives hosts like this to the on-shift analyst.",
              "Decision: the analyst acts without waiting. On a larger system, the same question has another answer.",
            ],
          },
          fold: true,
        },
        rounds: [
          {
            id: "stale",
            state: "An alert reads 'Encryption behaviour', HMT-APP-03, nine hours old. The file activity graph for the last hour is flat, and nobody has looked at it yet.",
            wires: [
              { id: "power", label: "Power it off in case it restarts" },
              { id: "isolate", label: "Isolate it at once: the word encryption is enough" },
              { id: "confirm", label: "Read the host's live file activity before acting" },
            ],
            cut: "confirm",
            hint: "How old is this, and does the graph agree with the alert?",
            why: "A nine-hour-old alert with a flat graph may be stale, or finished. Either way the first move is to establish what is true now. Acting on the title alone spends evidence, or uptime, for nothing.",
          },
          {
            id: "quiet",
            state: "HMT-CON-03 calls an outside address every 10 minutes. No files are changing. The firewall shows two more workstations calling the same address, and nobody knows how many others do.",
            wires: [
              { id: "scope", label: "Leave it running for now, and size the problem quietly" },
              { id: "isolate", label: "Shut this one switch port now, then go looking for the others" },
              { id: "power", label: "Power it off before the next call" },
            ],
            cut: "scope",
            hint: "Is anything burning? And do you know the size of this yet?",
            why: "Nothing is being destroyed and the scope is open. Cutting one host tells a watching attacker to speed up or pivot, and you lose the beacon before you have seen where else it goes.",
          },
          {
            id: "burn",
            state: "HMT-CON-03 is now rewriting the Loans share on HMT-FS-02 over SMB at 900 files a minute. A dump here takes 9 minutes. The courier schedule folder has about 4 minutes left.",
            wires: [
              { id: "dump", label: "Let the dump finish, then cut it off: the evidence is worth it" },
              { id: "power", label: "Hold the power button: nothing is faster" },
              { id: "port", label: "Shut its switch port now, and dump on the isolated host afterwards" },
            ],
            cut: "port",
            hint: "This writes over the network. What stops it, and what does that leave in RAM?",
            why: "Active destruction outweighs a dump you cannot finish in time, though had it fitted in the time left, it would have been worth taking. The encryption runs over SMB, so cutting the network stops it while RAM stays intact for a dump afterwards. Power-off stops it too, but destroys everything in memory for no extra gain.",
          },
          {
            id: "legal",
            state: "HMT-COLL-01 shows signs of the same intruder. The lender's insurers may need this evidence. The server runs ticketing for all five museums, and the on-shift analyst's playbook does not cover it.",
            wires: [
              { id: "alone", label: "Analyst decides now and records the reason afterwards" },
              { id: "commander", label: "Escalate to the incident commander, and collect under the plan's evidence rules" },
              { id: "rebuild", label: "Rebuild it from backup tonight, so it is clean for the opening" },
            ],
            cut: "commander",
            hint: "Whose decision is this, on a server this size?",
            why: "Legal exposure, wide impact and no playbook are what escalation paths are for. A rebuild destroys the evidence the insurers may need. Deciding alone puts one analyst in the seat a plan was meant to fill.",
          },
        ],
        lesson: "There is no single right answer to preserve or contain. There is a right answer for this host, at this minute, under this plan. Ask what is burning, how far it goes, and whose decision it is.",
      },
    ],

    // ── Boss warm-up: the decisive signal, on other tools ──
    "mdf-ac1": [
      {
        kind: "queue",
        title: "Same Tool, Different Night",
        prompt: "The Trust's new detection fires on anti-forensic tooling, and the review queue is full. Same tools, very different nights. For each alert, read who ran it, from what, against what scope, and what IT confirms. Then rule on it.",
        console: "SIEM · Incidents · Rule group: Anti-forensics · Status: New",
        primer: {
          title: "The command is a question, not a verdict",
          points: [
            "**False positive:** the rule matched something it should not have. **Benign true positive:** the rule was right, the behaviour really happened, and it is authorised. **True positive:** it is a threat, so escalate.",
            "Read four fields before any verdict: the **parent process**, the **account**, the **scope** of the command line, and the **time** against the maintenance window.",
            "Scope matters. A job that touches a defined, narrow target behaves differently from a command aimed at one incriminating file or at everything at once.",
            "Then verify with IT. A change record must match **this host, this account and this time**. A ticket for another host proves nothing, and a stolen service account keeps its usual name.",
            "A frightening tool name alone is not a finding. A calm-looking one is not an all-clear.",
          ],
          example: {
            label: "The method, on a log archive job",
            lines: [
              "Alert: `wevtutil epl Security E:\\archive\\sec.evtx`, parent `LogArchiver.exe`, account `svc-logarchive`, 01:00.",
              "Scope: one export to the archive volume. Time: the nightly window. IT: change record covers this host and job.",
              "Verdict: benign true positive. Close it, cite the change number.",
            ],
          },
          fold: true,
        },
        actions: [
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "tp", label: "Escalate: true positive", tone: "escalate" },
        ],
        alerts: [
          {
            id: "zero", time: "Sun 03:00", severity: "Medium", rule: "Secure delete tool executed", entity: "HMT-IMG-01",
            fields: [{ k: "Process", v: "sdelete64.exe" }, { k: "ParentProcess", v: "ImageStoreMaint.exe" }, { k: "Account", v: "HARROWGATE\\svc-imaging" }, { k: "CommandLine", v: "sdelete64.exe -accepteula -z E:" }],
            context: "IT confirms change CHG-5521: monthly free-space zeroing of the image store on HMT-IMG-01, Sundays at 03:00, run by ImageStoreMaint under svc-imaging.",
            answer: "btp",
            why: "The rule was right that SDelete ran, and every field matches the record: documented parent, service account, one volume, -z for free space only, on schedule. Benign true positive.",
          },
          {
            id: "wipe", time: "Sat 02:47", severity: "High", rule: "Secure delete tool executed", entity: "HMT-COLL-01",
            fields: [{ k: "Process", v: "sdelete64.exe" }, { k: "ParentProcess", v: "cmd.exe" }, { k: "Account", v: "HARROWGATE\\adm.thorne" }, { k: "CommandLine", v: "sdelete64.exe -accepteula -p 3 C:\\Users\\Public\\fsops.dll" }],
            context: "IT says no work was planned on this server this weekend, and the owner of adm.thorne is on leave.",
            answer: "tp",
            why: "Same tool, but aimed at a single file from a shell, in the small hours, by an admin account whose owner is away, with nothing on record. That is a clean-up, and the file name ties to this case.",
          },
          {
            id: "borrowed", time: "Sat 03:12", severity: "High", rule: "USN journal deleted", entity: "HMT-COLL-01",
            fields: [{ k: "Process", v: "fsutil.exe" }, { k: "ParentProcess", v: "powershell.exe" }, { k: "Account", v: "HARROWGATE\\svc-imaging" }, { k: "CommandLine", v: "fsutil usn deletejournal /d C:" }, { k: "Analyst note", v: "Service account, see CHG-5521" }],
            context: "IT says CHG-5521 covers HMT-IMG-01 only, and svc-imaging has no reason to log on to the collections server.",
            answer: "tp",
            why: "The account name looks routine and a ticket is quoted, but the ticket does not cover this host and the parent is a shell. A record that matches on the account alone is not a match.",
          },
          {
            id: "list", time: "Tue 11:20", severity: "Low", rule: "Shadow copies deleted", entity: "HMT-APP-03",
            fields: [{ k: "Process", v: "vssadmin.exe" }, { k: "ParentProcess", v: "cmd.exe" }, { k: "Account", v: "HARROWGATE\\adm.okoye" }, { k: "CommandLine", v: "vssadmin list shadows" }],
            context: "IT says adm.okoye belongs to the storage administrator, who was checking free space. Nothing was removed.",
            answer: "fp",
            why: "The rule claims a deletion but matched on the process name, and this command only lists. What it reported never happened, so it is a false positive and a reason to tighten the rule to delete verbs.",
          },
          {
            id: "retire", time: "Wed 14:05", severity: "Medium", rule: "Secure delete tool executed", entity: "HMT-APP-03",
            fields: [{ k: "Process", v: "cipher.exe" }, { k: "ParentProcess", v: "cmd.exe" }, { k: "Account", v: "HARROWGATE\\adm.okoye" }, { k: "CommandLine", v: "cipher /w:D:\\" }],
            context: "IT confirms change CHG-5544: decommission of HMT-APP-03, signed off by the data owner, with a free-space wipe of D: assigned to adm.okoye on Wednesday afternoon.",
            answer: "btp",
            why: "A human at a shell looks worse than a service, but this record names the host, the account, the step and the day. The wipe really happened and it was authorised. Benign true positive.",
          },
        ],
      },
    ],
  },
};
