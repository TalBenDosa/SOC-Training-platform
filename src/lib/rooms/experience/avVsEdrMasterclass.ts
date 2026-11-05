import type { RoomExperience } from "./types";

// "Operation Second Opinion" for the "av-vs-edr-masterclass" room.
// Script: docs/campaign/49-av-vs-edr-masterclass.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Wrenfield Veterinary Group (fictional), not the graded tasks' MedCore WS-EXEC-022.
// Signature mechanic: locks (the four layers of antivirus as doors to open).
// Lab data differs from the graded tasks: the doors and the sort never use
// AMSI, encoded PowerShell or named LOLBins (q1, q2) or entropy (r3 checkpoint);
// the sensor match leaves out AMSI (q1) and access masks (q3, r7 checkpoint);
// the hunt never touches LSASS, injection, PowerShell flags, containment or
// tamper protection (la1, f1, r9 checkpoint).
export const AV_VS_EDR_MASTERCLASS: RoomExperience = {
  roomId: "av-vs-edr-masterclass",
  codename: "Operation Second Opinion",
  theme: "avedr",
  handler: { name: "Beatriz Monteiro", role: "Head of IT Security, Wrenfield Veterinary Group" },
  briefing: [
    "Wrenfield Veterinary Group. 64 clinics, 700 staff, X-ray machines, pet records, and an antivirus console that has been green for six years.",
    "Last spring a clinic in Ludlow was encrypted over a weekend. The antivirus console stayed green the whole time.",
    "Beatriz Monteiro has budget for EDR, and a board that wants to know why the old tool wasn't enough. Her answer needs to be exact.",
    "Test what signatures can and can't do, see what only behaviour reveals, learn how a sensor sits inside the OS, hunt in a real console, then work a graded Falcon detection.",
  ],
  mission: "Beat a signature with one byte, open the four doors of antivirus, sort what AV sees from what only EDR sees, wire each sensor to its source, hunt in Advanced Hunting, then work the graded Falcon detection.",
  estimate: "~55 min",
  look: { primary: "#2dd4bf", secondary: "#f472b6", warn: "#facc15" },
  scene: "secondopinion",
  layout: "stage",
  stations: [
    {
      id: "oldguard",
      label: "The Old Guard",
      topic: "Endpoint security history · signatures · heuristics, sandboxing and ML",
      tagline: "Six years of green",
      building: "control",
      taskIds: ["edr-r1", "edr-r2", "edr-r3"],
    },
    {
      id: "blind",
      label: "Green Console",
      topic: "Why AV is not enough: fileless malware and living off the land",
      tagline: "What the scanner never saw",
      building: "lab",
      taskIds: ["edr-r4", "edr-q1", "edr-q2"],
    },
    {
      id: "sensor",
      label: "Under the Hood",
      topic: "What EDR is · kernel drivers and ETW",
      tagline: "A sensor inside the OS",
      building: "office",
      taskIds: ["edr-r5", "edr-r6"],
    },
    {
      id: "consoles",
      label: "Three Consoles",
      topic: "CrowdStrike Falcon · SentinelOne · Microsoft Defender XDR",
      tagline: "Hunt like you own one",
      building: "vault",
      taskIds: ["edr-r7", "edr-r8", "edr-r9", "edr-q3"],
    },
    {
      id: "opinion",
      label: "The Second Opinion",
      topic: "AV vs EDR vs XDR vs MDR · a live Falcon detection",
      tagline: "Work the graded detection",
      building: "ticket",
      taskIds: ["edr-r10", "edr-la1", "edr-f1"],
      boss: true,
    },
  ],
  personas: {
    "edr-q1": { name: "Beatriz Monteiro", role: "Head of IT Security", line: "Nothing touches the disk. Which tool catches it?" },
    "edr-q2": { name: "Beatriz Monteiro", role: "Head of IT Security", line: "The board asked what 'living off the land' means. Give me one clear answer." },
    "edr-q3": { name: "Beatriz Monteiro", role: "Head of IT Security", line: "0x1FFFFF on LSASS. What does that mask mean?" },
    "edr-la1": { name: "Beatriz Monteiro", role: "Head of IT Security", line: "A Falcon Critical on an executive's laptop. Read the detection." },
    "edr-f1": { name: "Beatriz Monteiro", role: "Head of IT Security", line: "Where is the attacker's code running now? Give me the PID." },
  },
  briefings: {
    // ── Reading 2: beat a signature ──
    "edr-r2": [
      {
        kind: "terminal",
        title: "Beat the Signature",
        prompt: "Beatriz keeps two copies of the dropper from the Ludlow clinic on an isolated Linux box. Scan them with ClamAV, then find out how little it takes to get past a hash signature.",
        shell: "bash",
        host: "beatriz@wf-lab-01:~/samples$",
        commands: [
          { match: "clamscan\\s+.*", help: "clamscan --no-summary *.exe   scan every sample",
            output: "/home/beatriz/samples/ludlow-a.exe: Win.Dropper.WrenTest-10023 FOUND\n/home/beatriz/samples/ludlow-b.exe: OK" },
          { match: "sha256sum\\s+.*", help: "sha256sum *.exe   fingerprint each sample",
            output: "7f3c9a1e5b2d48c06e11d9a4c2b7f8e03a65d1c49e7b20f8ad13c6e5f0b94d27  ludlow-a.exe\nc24e81d70fa93b6e15d82c7a0e4f96b3187ca5d2e06b9f43d1a7e8c05b3f6a19  ludlow-b.exe" },
          { match: "cmp\\s+-l\\s+.*", help: "cmp -l ludlow-a.exe ludlow-b.exe   list every byte that differs",
            output: "204817 101 102" },
        ],
        objectives: [
          { id: "sig", task: "Which sample does ClamAV flag?", hint: "clamscan --no-summary *.exe", answer: ["ludlow-a.exe", "ludlow-a"], why: "Only ludlow-a matches a signature. ludlow-b comes back OK." },
          { id: "hash", task: "Do the two samples have the same SHA-256? (yes/no)", hint: "sha256sum *.exe", answer: ["no"], why: "Completely different fingerprints." },
          { id: "bytes", task: "How many bytes differ between them?", hint: "cmp -l ludlow-a.exe ludlow-b.exe", answer: ["1"], why: "One line of output, one byte. Same program, new hash, and a hash signature no longer matches." },
        ],
      },
    ],
    // ── Reading 3: signature mechanic, four doors ──
    "edr-r3": [
      {
        kind: "locks",
        title: "Four Doors of the Old Guard",
        prompt: "Modern antivirus is four layers stacked up. Read each door's idea and what it did on a Wrenfield laptop, then answer its check to open it.",
        locks: [
          {
            id: "sig", letter: "1", name: "Signatures",
            idea: "Compare a file against a list of known bad patterns.",
            example: "A known dropper lands in a receptionist's Downloads folder. It matches the list and is quarantined in under a second.",
            check: { q: "What is this door's weakness?", options: ["It only knows what is already on the list", "It runs too slowly to use on real files"], answer: 0, why: "Fast and precise, but blind to anything not yet seen." },
          },
          {
            id: "heur", letter: "2", name: "Heuristics",
            idea: "Score a file on suspicious traits, without needing an exact match.",
            example: "An unknown installer imports functions for keylogging and adds itself to startup. The score crosses the line and it is flagged.",
            check: { q: "What is the price of scoring on traits?", options: ["More false positives on odd but legitimate software", "It can never detect a new file"], answer: 0, why: "A strange in-house billing tool can score just like malware." },
          },
          {
            id: "sand", letter: "3", name: "Sandbox",
            idea: "Run the file somewhere safe and watch what it does.",
            example: "An attachment is detonated in a virtual machine for two minutes, and the sandbox records what it tried to do.",
            check: { q: "A sample sleeps for ten minutes before acting. What does the two-minute sandbox see?", options: ["Nothing suspicious: it timed out first", "The full attack, because sandboxes skip all waits"], answer: 0, why: "Delays and environment checks are the classic way out of a sandbox." },
          },
          {
            id: "ml", letter: "4", name: "Machine learning",
            idea: "A model trained on millions of files predicts whether a new one is bad.",
            example: "A never-seen file gets a 0.97 malicious score from features of its structure, with no signature at all.",
            check: { q: "All four doors share one limit. What is it?", options: ["They judge files, so they need a file to judge", "They only work on Linux"], answer: 0, why: "Every door here starts from an object to inspect. Hold that thought for the next station." },
          },
        ],
      },
    ],
    // ── Reading 4: what each tool sees ──
    "edr-r4": [
      {
        kind: "sort",
        title: "What the Scanner Saw",
        prompt: "The Ludlow weekend, event by event. Which of these could the antivirus have judged, and which show up only as behaviour over time?",
        buckets: [
          { id: "av", label: "AV can judge it" },
          { id: "edr", label: "Only behaviour shows it" },
        ],
        items: [
          { id: "known", text: "A dropper with a known hash saved to Downloads", bucket: "av", why: "A file, on disk, on the list." },
          { id: "usb", text: "An infected file copied from a USB stick", bucket: "av", why: "A file arriving: exactly what real-time scanning is for." },
          { id: "child", text: "The accounts app suddenly starts a command shell", bucket: "edr", why: "Each program is fine. The parent and child together are what's wrong." },
          { id: "night", text: "A receptionist's account running admin tools at 03:00 on Sunday", bucket: "edr", why: "Nothing about the file changed. The who and the when did." },
          { id: "chain", text: "Five ordinary actions that only look wrong in that order", bucket: "edr", why: "It takes a recorded timeline to see a chain." },
          { id: "macro", text: "A document carrying a macro already on the signature list", bucket: "av", why: "Known content in a file is still a signature match." },
        ],
      },
    ],
    // ── Reading 6: sensors ──
    "edr-r6": [
      {
        kind: "match",
        title: "Wire the Sensor",
        prompt: "An EDR agent listens at several points inside Windows. Match each sensor to what it reports.",
        pairs: [
          { id: "proc", left: "Kernel process callback", right: "A new process starting, and its parent", why: "PsSetCreateProcessNotifyRoutine: the driver hears every process start." },
          { id: "file", left: "File system minifilter", right: "Files created or written", why: "A minifilter driver sits in the path of disk operations." },
          { id: "reg", left: "Registry callback", right: "Keys and values changed", why: "CmRegisterCallback reports registry operations." },
          { id: "net", left: "Windows Filtering Platform callout", right: "Network connections", why: "WFP shows which process connected where." },
          { id: "etw", left: "Event Tracing for Windows provider", right: "Events the OS and runtimes publish, like .NET loads", why: "ETW lets a sensor subscribe to what Windows components already report." },
        ],
      },
    ],
    // ── Reading 9: Advanced Hunting ──
    "edr-r9": [
      {
        kind: "terminal",
        title: "Hunt in Defender",
        prompt: "Wrenfield is trialling Defender XDR. A clinic reported a strange pop-up. Hunt it down in Advanced Hunting.",
        shell: "bash",
        host: "Advanced hunting > ",
        commands: [
          { match: "^deviceprocessevents\\s*\\|\\s*where\\s+filename\\s*==\\s*\"mshta\\.exe\".*", help: "DeviceProcessEvents | where FileName == \"mshta.exe\" | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName",
            output: "Timestamp            DeviceName     AccountName  InitiatingProcessFileName\n---------            ----------     -----------  -------------------------\n2026-11-03 10:42:18  VET-RECEP-14   k.bowen      OUTLOOK.EXE" },
          { match: "^devicenetworkevents\\s*\\|\\s*where\\s+devicename\\s*==\\s*\"vet-recep-14\".*", help: "DeviceNetworkEvents | where DeviceName == \"VET-RECEP-14\" and InitiatingProcessFileName == \"mshta.exe\" | project Timestamp, RemoteUrl, RemotePort",
            output: "Timestamp            RemoteUrl                     RemotePort\n---------            ---------                     ----------\n2026-11-03 10:42:21  files.vet-supplies.example    443" },
        ],
        objectives: [
          { id: "dev", task: "Which device ran mshta.exe?", hint: "DeviceProcessEvents | where FileName == \"mshta.exe\" | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName", answer: ["vet-recep-14"], why: "One row, one reception PC." },
          { id: "parent", task: "Which program started it?", hint: "Read the InitiatingProcessFileName column.", answer: ["outlook.exe", "outlook"], why: "A mail client starting an HTML application host: a parent and child that rarely belong together." },
          { id: "url", task: "Which site did it reach out to?", hint: "DeviceNetworkEvents | where DeviceName == \"VET-RECEP-14\" and InitiatingProcessFileName == \"mshta.exe\" | project Timestamp, RemoteUrl, RemotePort", answer: ["files.vet-supplies.example"], why: "Process table to network table, joined by the device and the process. That pivot is what the telemetry buys you." },
        ],
      },
    ],
  },
};
