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
        kind: "duel",
        title: "Evasion Against the Old Guard",
        prompt: "Beatriz replays the Ludlow crew's playbook against Wrenfield's defences. Each move is an evasion that works on one control. Play the control that still holds, and remember a played card is gone.",
        attacker: "The Ludlow crew",
        moves: [
          { id: "m1", move: "Change one byte of a known dropper", detail: "Same program, same behaviour. The SHA-256 is completely different and the old signature no longer matches.", counter: "model", hint: "The file is new to the list but still looks like its family.", why: "A trained model scores the file's structure and traits, so one flipped byte barely moves its score. Adding the new hash to the blocklist works once, and the crew flips another byte." },
          { id: "m2", move: "Sleep ten minutes before doing anything", detail: "The file waits quietly. The mail sandbox watches an attachment for two minutes and then lets it go.", counter: "sensor", hint: "Your watcher has to stay with the file after it is delivered.", why: "A sensor on the real endpoint watches behaviour whenever it starts, and it has no timeout. Extending the sandbox to five minutes is still a number the attacker can beat with a longer sleep." },
          { id: "m3", move: "Use the accounts app to start a command shell", detail: "Both programs are legitimate and signed. Only the pair is wrong.", counter: "pair", hint: "Neither file is bad. What is odd is who launched whom.", why: "A parent and child rule fires on the pair, which is where EDR sees what file scanning cannot. A heuristic file score judges each file by itself, and both files are clean." },
          { id: "m4", move: "Three quiet weeks of normal-looking admin work", detail: "Nothing was blocked. Someone finally asks what the accounts server did last month.", counter: "history", hint: "Today's scan cannot answer a question about last month.", why: "Recorded telemetry lets you search back in time and rebuild the intrusion. A fresh signature rescan inspects files, and the intruder left none that match anything." },
          { id: "m5", move: "A receptionist account runs admin tools at 03:00 on Sunday", detail: "Nothing about any file is wrong. The account and the hour are.", counter: "baseline", hint: "The tool is allowed. The person and the time are not usual.", why: "Comparing who normally runs what, and when, exposes a valid account used out of pattern. No file-based control has any opinion about an account at 03:00." },
        ],
        cards: [
          { id: "model", name: "Machine-learning file score", effect: "Predicts from a file's structure and traits whether it is malicious." },
          { id: "sensor", name: "Endpoint sensor with no timeout", effect: "Watches process behaviour for as long as the host runs." },
          { id: "pair", name: "Parent and child process rule", effect: "Alerts when one program starts another it never normally starts." },
          { id: "history", name: "Search recorded telemetry", effect: "Looks back through weeks of process, file and network events." },
          { id: "baseline", name: "Who-and-when baseline", effect: "Flags an account doing something outside its usual pattern." },
          { id: "hash", name: "Add the new hash to the blocklist", effect: "Blocks the exact file whose SHA-256 you provide." },
          { id: "rescan", name: "Rescan every disk with fresh signatures", effect: "Checks every file again against the latest signature set." },
        ],
        lesson: "A hash signature is defeated by one changed byte, since the fingerprint of the file is all it knows. Each later control moves the question elsewhere: what the file resembles, how it behaves over time, which pair of programs ran, what happened last month and who did it at what hour. The blocklist and the rescan are real controls, but both still judge only files.",
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
        kind: "tune",
        title: "Tune the Hunt in Advanced Hunting",
        prompt: "A clinic reported a strange pop-up, and a hunting query over DeviceProcessEvents returns twelve odd parent and child chains from the last week. Set a behaviour score floor and a prevalence ceiling so the query keeps the intrusions and drops Wrenfield's own tooling. A hit is where the hunt starts: you then pivot to DeviceNetworkEvents by device and process.",
        eventColumn: "Chain seen in DeviceProcessEvents",
        dials: [
          { id: "score", label: "Minimum behaviour score", short: "Score", unit: "pts", min: 0, max: 100, step: 1, start: 0, dir: "above" },
          { id: "hosts", label: "Maximum hosts that run this chain", short: "Hosts", unit: "hosts", min: 1, max: 400, step: 1, start: 400, dir: "below" },
        ],
        mode: "all",
        events: [
          { id: "b1", label: "Outlook starts an HTML application host that reaches a new website", bad: true, values: { score: 82, hosts: 1 } },
          { id: "b2", label: "Word starts a shell with a hidden window", bad: true, values: { score: 76, hosts: 2 } },
          { id: "b3", label: "Accounts app starts a command shell on a clinic PC", bad: true, values: { score: 64, hosts: 6 } },
          { id: "b4", label: "Reception account runs admin tools, in a chain with a new service", bad: true, values: { score: 58, hosts: 3 } },
          { id: "b5", label: "Five ordinary actions in an unusual order on one workstation", bad: true, values: { score: 47, hosts: 8 } },
          { id: "g1", label: "Software deployment tool runs its installer script", bad: false, values: { score: 71, hosts: 380 } },
          { id: "g2", label: "Nightly backup job compresses and uploads to the vendor", bad: false, values: { score: 68, hosts: 64 } },
          { id: "g3", label: "Helpdesk remote-support session on a clinic PC", bad: false, values: { score: 61, hosts: 9 } },
          { id: "g4", label: "X-ray viewer updater, unsigned, on imaging PCs", bad: false, values: { score: 55, hosts: 10 } },
          { id: "g5", label: "IT admin runs a patch script on the accounts server", bad: false, values: { score: 49, hosts: 4 } },
          { id: "g6", label: "Practice software opens its PDF viewer", bad: false, values: { score: 22, hosts: 2 } },
          { id: "g7", label: "Browser starts its updater", bad: false, values: { score: 15, hosts: 400 } },
        ],
        goal: { catch: 4, maxFalse: 1 },
        deploys: 3,
        lesson: "Neither dial works alone. A low prevalence ceiling by itself keeps the odd benign chain, and a high score floor by itself keeps the deployment tool and the backup job. Together they drop what many hosts do every night and keep what one or two hosts did once. Expect to lose the slow, low-scoring chain at a strict floor, because that is the case where telemetry and a human hunter earn their keep. An Outlook parent starting an HTML application host is the pivot: join to the network table on device and process to find where it went.",
      },
    ],
  },
};
