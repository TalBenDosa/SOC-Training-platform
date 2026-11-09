import type { RoomExperience } from "./types";

// "Operation Loose Thread" for the "investigation-methodology" room.
// Script: docs/campaign/61-investigation-methodology.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// TASK ORDER CHANGED: r1, q1 | r2, q2, q3 | r3, q5 | la1, flag1, q4. The room stored all
// three readings first, which cannot make stations. q4 must stay after la1 (it says "the
// logon above"), so the boss holds la1, flag1, q4 and q5 moves up beside its reading.
//
// St Aldric's Hospice Group (fictional charity), not the graded tasks' corp.local records.
// Signature: the Hypothesis Board. The learner forms a hypothesis (deduce), walks evidence
// sources where each hop must follow from the last finding and a wrong pivot says what it
// could never have proved (pathway), then rebuilds one UTC timeline from clocks in three
// zones (sequence).
// Game mix: deduce + hunt + pathway. The hunt is SPL, in its own tables.
// Lab data differs from the graded tasks: the rollover drill is a VPN buffer and laptop
// memory, never one server's Security log (q1); the IP-to-hosts pivot starts from an EDR
// process record, never a firewall beacon (q2); zones are UTC-3, UTC+1 and UTC+8, never
// UTC+2, and no lab merges an EVTX, an IIS log and Sentinel results (q3); the anatomy is a
// clean Kerberos logon by svc-crmsync that matches its inventory line, never svc-backup,
// SRV-FINANCE-02, WS-DEV-09, 10.0.1.45 or NTLM (la1, flag1); the hunt follows a named admin
// to a file server (la1); the sort never asks Event ID 7045, which appears only as data in
// the hunt and as a passing fact (q4); the ticket drill marks up one draft, never a choice
// of drafts (q5).

export const INVESTIGATION_METHODOLOGY: RoomExperience = {
  roomId: "investigation-methodology",
  codename: "Operation Loose Thread",
  theme: "loosethread",
  handler: { name: "Rafe Nakagawa", role: "Senior Investigator, St Aldric's Hospice Group" },
  briefing: [
    "St Aldric's Hospice Group. Three hospices, in Bristol, Halifax and Perth, and each one hosts a shared system nobody has ever moved.",
    "This afternoon a donor rang the fundraising office: a stranger had quoted the exact sum promised to the hospice in the donor's will.",
    "Rafe Nakagawa has one loose thread and one rule: no log gets opened until there is a question to ask it.",
    "Form a hypothesis, find the evidence that could kill it, follow each finding to the next, and write it up so anyone can check it.",
  ],
  mission: "Test hypotheses against evidence, sort a case into its phases, race a log's rollover, pivot from source to source, rebuild one timeline in UTC, climb an SPL search to the odd logons, mark up a draft ticket, then read the logon that ties the case off.",
  estimate: "~50 min",
  look: { primary: "#fb7185", secondary: "#7dd3fc", warn: "#fde047" },
  scene: "facilityloosethread",
  layout: "facility",
  story: {
    intro: { title: "The Exact Sum", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-intro-c9032a16.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-intro-fc32a32b.jpg" },
    afterStation: {
      question: { title: "What Would Prove It?", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-ch2-8cd0dc1f.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-ch2-f8003158.jpg" },
      pivot: { title: "Three Clocks, One Morning", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-ch3-a5c94f7c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-ch3-851636e1.jpg" },
      logon: { title: "Tied Off", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-finale-acf1b0e0.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/investigation-methodology/loosethread-finale-2de47619.jpg" },
    },
  },
  stations: [
    {
      id: "question",
      label: "The First Question",
      topic: "Detective mindset · reactive and proactive work · the six phases · collect before it is gone",
      tagline: "What would have to be true?",
      building: "reception",
      taskIds: ["inv-method-r1", "inv-method-q1"],
    },
    {
      id: "pivot",
      label: "Pivot and Timeline",
      topic: "Evidence pivoting · the four pivots · time zones · building a timeline in UTC",
      tagline: "Each finding picks the next source",
      building: "lab",
      taskIds: ["inv-method-r2", "inv-method-q2", "inv-method-q3"],
    },
    {
      id: "casefile",
      label: "SIEM and Case File",
      topic: "The SIEM workflow · entity context · lateral movement and exfiltration indicators · a good case ticket",
      tagline: "Can someone else check your work?",
      building: "office",
      taskIds: ["inv-method-r3", "inv-method-q5"],
    },
    {
      id: "logon",
      label: "Read the Logon",
      topic: "One logon record against its inventory · the next pivot · what the next result means",
      tagline: "One record, one call",
      building: "ticket",
      taskIds: ["inv-method-la1", "inv-method-flag1", "inv-method-q4"],
      boss: true,
    },
  ],
  personas: {
    "inv-method-q1": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "The case is scoped. Tell me your next move." },
    "inv-method-q2": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "One host so far. I want your next search." },
    "inv-method-q3": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "Three sources, one timeline. Which one worries you?" },
    "inv-method-q5": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "Someone else picks this up tomorrow, without you." },
    "inv-method-la1": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "Read the record against the inventory note." },
    "inv-method-flag1": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "Give me the value you would search for." },
    "inv-method-q4": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "The results are back. Tell me what each one means." },
  },
  briefings: {
    // ── Reading 1: mindset and lifecycle ──
    "inv-method-r1": [
      {
        kind: "deduce",
        title: "Kill the Hypotheses",
        prompt: "This afternoon, the fundraising office. A stranger has quoted a donor the exact sum promised in the donor's will, and that sum lives in the Legacy Register, inside the CRM (customer relationship management system, here the donor database). Rafe puts six explanations on the board, each with what it predicts. Strike one out only when a clue contradicts its prediction, then name the one left standing.",
        nameColumn: "Hypothesis",
        columns: ["Holds the sums?", "Reads through the CRM?", "Login in the audit log", "Officer at the desk?"],
        suspects: [
          { id: "mailing", name: "The mailing house", cells: ["No, names and addresses", "No", "None", "Not needed"] },
          { id: "solicitor", name: "One solicitor's office", cells: ["Yes, for its own client", "No", "None", "Not needed"] },
          { id: "vendor", name: "The CRM vendor's support desk", cells: ["Yes, every donor", "Yes", "Support login, open ticket", "Not needed"] },
          { id: "stolen", name: "An outsider with a staff login", cells: ["Yes, every donor", "Yes", "A legacy officer's login", "No, could be anywhere"] },
          { id: "share", name: "An old export on an open share", cells: ["Yes, every donor", "No, it reads a file", "None", "Not needed"] },
          { id: "insider", name: "A legacy officer selling it", cells: ["Yes, every donor", "Yes", "A legacy officer's login", "Yes, at the keyboard"] },
        ],
        clues: [
          "Three donors have now rung. They use three different solicitors, and each caller quoted the exact sum.",
          "The CRM audit log, the application's own record of who read what, shows all three records were read through the application.",
          "Those reads ran under a staff login. The vendor's support login has not been used since August, and no ticket is open.",
          "The rota puts that officer at a family's home, with the laptop left in the office, for the whole of those reads.",
        ],
        culprit: "stolen",
        why: "Only an outsider with a staff login predicts all four clues. The insider is the near miss: same login, same reads, and it fell only to a fact from outside the logs. That is the method: a hypothesis earns its place by saying what evidence would kill it. Think like the attacker too: someone who wants the sums takes the quietest way to them. And it is still a hypothesis, not a verdict, so the next evidence must be able to kill it as well. This case is reactive, because a report started it. A proactive hunt starts from a hypothesis before anything has fired.",
      },
      {
        kind: "sort",
        title: "Six Phases of One Case",
        prompt: "Rafe's notes from this case and two older ones, out of order. Every reactive investigation runs through six phases, and skipping one loses evidence or the conclusion. Put each note in its phase.",
        buckets: [
          { id: "trigger", label: "1. Trigger" },
          { id: "scope", label: "2. Scope" },
          { id: "collect", label: "3. Collect" },
          { id: "analyze", label: "4. Analyze" },
          { id: "conclude", label: "5. Conclude" },
          { id: "document", label: "6. Document" },
        ],
        items: [
          { id: "a1", text: "A donor rings the fundraising office about a stranger's call", bucket: "trigger", why: "A report from a person is a trigger, and an external one makes this a reactive case. Write down exactly what came in and when." },
          { id: "a2", text: "A threat feed hands over an address your firewall has seen", bucket: "trigger", why: "Another system feeding you an IOC (Indicator of Compromise) is a trigger too. So is an alert firing." },
          { id: "a3", text: "One officer's login, or every login that can reach the register?", bucket: "scope", why: "Scope is an early estimate of how big this might be, made before the data is pulled. It sets how much to collect." },
          { id: "a4", text: "All three hospices use this CRM, so tell the duty manager now", bucket: "scope", why: "Scope also sets how urgently you escalate. One host and the whole estate are different afternoons." },
          { id: "a5", text: "Pull the audit log and the officer's sign-in history into the case", bucket: "collect", why: "Collect the alert plus its context: process logs, authentication history, network traffic, endpoint telemetry." },
          { id: "a6", text: "Copy the laptop's memory before its patch restart", bucket: "collect", why: "Collection runs ahead of analysis because logs rotate and memory is lost when a machine restarts." },
          { id: "a7", text: "Line the sign-ins up in time and note what should be there but isn't", bucket: "analyze", why: "Analysis builds the timeline and hunts for anomalies, including absences: events that should exist and don't." },
          { id: "a8", text: "If I wanted the sums, why would I open this record first?", bucket: "analyze", why: "Attackers have goals and their steps follow a logic. Understanding the goal predicts what evidence to look for next." },
          { id: "a9", text: "True positive: the register was read from one laptop, 2,140 records", bucket: "conclude", why: "Conclude gives the verdict and, for a true positive, what the attacker did, which systems are affected and what data may have been accessed." },
          { id: "a10", text: "Inconclusive: the proxy log had rolled before anyone looked", bucket: "conclude", why: "There are three verdicts: true positive, false positive and inconclusive. An honest inconclusive is a conclusion too." },
          { id: "a11", text: "Add each piece of evidence and the reasoning to the case record", bucket: "document", why: "Document holds the trigger, the timeline, the evidence, the logic and the conclusion." },
          { id: "a12", text: "Write it so an outside response team could rely on it later", bucket: "document", why: "If a case reaches an incident response team or law enforcement, your write-up becomes the record of what happened." },
        ],
      },
    ],
    "inv-method-q1": [
      {
        kind: "worksheet",
        title: "What Disappears First",
        prompt: "Tuesday, 13:00 UTC. The activity you care about ran from about 02:00 UTC, so the oldest line you need is 11 hours old. Before you analyse anything, work out how long each source has left.",
        caption: "Evidence sources for this case",
        columns: ["source", "where it lives", "size limit", "write rate", "in the SIEM?"],
        rows: [
          ["VPN gateway log", "appliance buffer", "240 MB", "20 MB an hour", "partly"],
          ["Web proxy log", "ALD-PER-PX01 disk", "9 GB", "0.6 GB an hour", "no"],
          ["CRM audit log", "database table", "90 days", "not relevant", "yes"],
          ["Laptop memory", "ALD-PER-LT31", "lost on restart", "patch restart at 13:30 UTC", "no"],
        ],
        questions: [
          { id: "w1", q: "How many hours of history does the VPN buffer hold?", hint: "Size limit divided by write rate.", answer: ["12", "12 hours"], why: "240 / 20 = 12 hours. A buffer is a ring: the newest line overwrites the oldest." },
          { id: "w2", q: "In how many hours will it overwrite the oldest line you need?", hint: "History held, minus the age of that line.", answer: ["1", "1 hour"], why: "12 - 11 = 1 hour. 'Partly in the SIEM' does not save you, because you can't yet say which lines were forwarded." },
          { id: "w3", q: "The same question for the web proxy log, in hours.", hint: "Work out its history first.", answer: ["4", "4 hours"], why: "9 / 0.6 = 15 hours of history, and 15 - 11 = 4 hours left." },
          { id: "w4", q: "Which source do you go for first?", hint: "Which deadline is nearest?", answer: ["laptop memory", "memory", "ram", "the laptop", "laptop", "ald-per-lt31"], why: "Thirty minutes beats one hour. Ask IT to hold the restart and capture memory, then take the VPN log, then the proxy log. A restart would destroy that memory, so restarting first is never a containment step. Collect, then analyse: analysis can wait, and these deadlines can't." },
        ],
      },
    ],
    // ── Reading 2: pivoting and timelines ──
    "inv-method-r2": [
      {
        kind: "match",
        title: "Four Pivots",
        prompt: "A pivot starts from one piece of evidence and uses it to find more. Rafe pins four questions from past cases on the board. Match each one to the pivot that answers it.",
        pairs: [
          { id: "p1", left: "A rogue DLL's SHA-256 turned up on one laptop. Is it anywhere else?", right: "File hash to hosts", why: "Query your EDR (Endpoint Detection and Response) platform for every machine holding that hash. One infected machine can mean fifty." },
          { id: "p2", left: "You no longer trust a fundraiser's login. Where has it been?", right: "User account to systems", why: "Ask the authentication logs, going back about 30 days. Machines that login has no reason to touch are how lateral movement shows itself." },
          { id: "p3", left: "An odd powershell.exe sits on a kiosk PC. Who is it talking to?", right: "Process to network connections", why: "EDR network telemetry ties connections to the process that opened them, which is how you find an attacker's C2 (command-and-control) server or exfiltration target." },
          { id: "p4", left: "A phishing kit's landing page lives at one address. Which of our machines went there?", right: "IP address to hosts", why: "Ask the proxy, firewall or DNS logs which of your machines reached it. A reputation site only says what the world thinks of the address." },
        ],
      },
      {
        kind: "pathway",
        title: "The Hypothesis Board",
        prompt: "On the board: 'An outsider is using a real staff login to read the Legacy Register.' Each stop is an evidence source, and the only valid next stop is the one your last finding points to. Before each hop ask what that source could prove or kill.",
        goal: "Prove or kill the hypothesis, one pivot at a time",
        nodes: [
          { id: "board", label: "The hypothesis", sub: "Outsider, real login", x: 10, y: 50 },
          { id: "crm", label: "CRM audit log", sub: "Who read the records?", x: 30, y: 50 },
          { id: "adgrp", label: "AD group list", sub: "What a login may reach", x: 30, y: 16 },
          { id: "av", label: "Antivirus console", sub: "Scan results", x: 30, y: 84 },
          { id: "signin", label: "Sign-in logs", sub: "Account to systems", x: 50, y: 30 },
          { id: "doors", label: "Door badge log", sub: "Who was in the building", x: 50, y: 70 },
          { id: "edr", label: "EDR process tree", sub: "Process to connections", x: 70, y: 18 },
          { id: "ti", label: "Reputation lookup", sub: "What others have seen", x: 90, y: 34 },
          { id: "proxy", label: "Web proxy log", sub: "IP to hosts", x: 88, y: 62 },
          { id: "fw", label: "Firewall flows", sub: "Bytes out", x: 68, y: 84 },
        ],
        edges: [["board", "crm"], ["board", "adgrp"], ["board", "av"], ["crm", "signin"], ["crm", "doors"], ["crm", "av"], ["signin", "edr"], ["signin", "adgrp"], ["signin", "doors"], ["edr", "ti"], ["edr", "proxy"], ["proxy", "ti"], ["proxy", "fw"]],
        route: ["board", "crm", "signin", "edr", "proxy", "fw"],
        notes: {
          board: "Kill test first. If someone read the register, the application must hold a record of those reads. If it holds none, this hypothesis is dead. Which source would show that?",
          crm: "Finding: l.tran's login exported 2,140 legacy records at 02:48 UTC. You now hold a user, so the pivot is user account to systems: where else has this login been?",
          signin: "Finding: one device only, ALD-PER-LT31, the officer's own laptop, used while the officer was out. The hypothesis bends: no remote sign-in, so something on that laptop did this. What ran there?",
          edr: "Finding: rundll32.exe on the laptop connected to 203.0.113.58. Process to network connections has handed you an external address. Scope is the next question: who else called it?",
          proxy: "Finding: ALD-HFX-WS07 in Halifax called the same address. One laptop just became two hosts, and that came from IP to hosts. The question left is whether anything got out.",
          fw: "Finding: 1.4 GB out to 203.0.113.58. The hypothesis has now survived every test that could have killed it, and that survival is what a true positive rests on.",
        },
        traps: {
          adgrp: "Group membership in AD (Active Directory) shows what a login may reach, not what it did. It could never prove anyone used it, so it neither proves nor kills this hypothesis.",
          av: "A clean scan kills nothing here. A stolen login leaves no file to find, so an antivirus result could never show who read the register.",
          doors: "A badge places a person in a building. It could never show what an account did on a server, and a remote intruder never touches a door.",
          ti: "Reputation tells you what other people have seen at an address. It could never show which St Aldric's machines called it, or how many bytes left.",
        },
        lesson: "A source can only answer what it records, so ask what it could prove or kill before you open it. Let each finding pick the next search: a user points to systems, a process to connections, an address to hosts, a file hash to hosts. And let the hypothesis bend when a finding bends it.",
      },
      {
        kind: "inspect",
        title: "Whose Clock Is This?",
        prompt: "Before you merge anything, check what each source's timestamp really means. Open each line from Rafe's field guide. The trap is rarely a wrong clock. It is a clock nobody asked about.",
        artifact: "Timestamps from six sources, as written",
        items: [
          { id: "t1", text: "<TimeCreated SystemTime=\"2026-10-13T02:23:05.114Z\"/>", tag: "UTC in the record", tone: "trust", note: "Windows Event Log stores TimeCreated in UTC (Coordinated Universal Time). It is the Event Viewer display that converts to the viewer's local time, so check which view you are reading." },
          { id: "t2", text: "2026-10-13 02:31:09 10.40.2.20 GET /pledges 443 200", tag: "UTC, no marker", tone: "trust", note: "An IIS web server log in W3C format. It is UTC even though the line shows no zone: the format tells you, not the line." },
          { id: "t3", text: "10.40.2.21, -, 10/13/26, 3:31:09, W3SVC1, ALD-CRM-01, ...", tag: "Local time", tone: "warn", note: "An older-format IIS log. The older IIS format is written in the server's local time, so a server's own zone setting belongs in your notes." },
          { id: "t4", text: "2026-10-13 03:48:12 INFO export job started", tag: "No zone: ask", tone: "warn", note: "Many application logs write the server's local time and say nothing about it. Find the zone, record it, convert by hand." },
          { id: "t5", text: "Oct 12 23:58:31 fw-hfx-01 kernel: ACCEPT OUT=eth0", tag: "No zone, no year", tone: "warn", note: "Some syslog sources write local time with no zone and no year. Sorted as text, this line lands in the wrong day." },
          { id: "t6", text: "_time 2026-10-13 02:23:05", tag: "Verify the view", tone: "info", note: "Sentinel, Splunk and Elastic normalise to UTC in most setups, but a console can display your profile's zone. Confirm it is showing UTC before you copy a time out." },
        ],
      },
      {
        kind: "sequence",
        title: "One Timeline in UTC",
        prompt: "The same morning from six sources, each printed the way its own system prints it. Convert each one to UTC, then tap them from earliest to latest. Halifax runs three hours behind UTC this week, Bristol one ahead, Perth eight ahead.",
        items: [
          { id: "fw", text: "Firewall, Halifax (UTC-3): Mon 12 Oct 23:58:31. 1.4 GB out to 203.0.113.58", note: "02:58:31 UTC, Tuesday. Add 3 hours and the date rolls over." },
          { id: "crm", text: "CRM application log, Bristol (UTC+1): Tue 13 Oct 03:48:12. l.tran exports 2,140 records", note: "02:48:12 UTC. Subtract 1 hour." },
          { id: "siem", text: "SIEM alert (UTC): Tue 13 Oct 03:20:00. Low: rare outbound destination", note: "03:20:00 UTC. The SIEM (Security Information and Event Management platform) is already in UTC." },
          { id: "proxy", text: "Web proxy, Perth (UTC+8): Tue 13 Oct 10:21:40. ALD-PER-LT31 opens giftaid-form.example", note: "02:21:40 UTC. Subtract 8 hours." },
          { id: "mail", text: "Mail gateway, Halifax (UTC-3): Mon 12 Oct 23:14:08. 'Gift Aid form' delivered to l.tran", note: "02:14:08 UTC, Tuesday. Add 3 hours and the date rolls over." },
          { id: "edr", text: "EDR (UTC): Tue 13 Oct 02:23:05. rundll32.exe starts on ALD-PER-LT31", note: "02:23:05 UTC. Already in UTC." },
        ],
        order: ["mail", "proxy", "edr", "crm", "fw", "siem"],
        doneNote: "Sorted by the printed clocks, the data leaves before the malware runs and the click comes last: a story that never happened. In UTC it reads straight: mail, click 7 minutes later, code running, export, and 1.4 GB gone 21 minutes before the alert fired. That is what a timeline answers: when the first foothold was, how long until the next move, whether the data left before the alert, and whether they came back. So work in UTC, search 24 to 48 hours either side of the trigger across the same user, host and IP, and tag every line with its source. Sentinel's Investigation Graph and the MDE (Microsoft Defender for Endpoint) Timeline tab help, and a shared spreadsheet is enough for a small case.",
      },
    ],
    // ── Reading 3: SIEM workflow and case management ──
    "inv-method-r3": [
      {
        kind: "queue",
        title: "Same Rule, Different Entity",
        prompt: "Steps 1 to 3 of the SIEM workflow: read the alert, widen the window to at least 24 hours either side, and find out what each host, user and IP normally is. Rafe hands you four alerts. Decide each one from the entity's context, not from the severity.",
        console: "SIEM · Incidents · Status: New",
        actions: [
          { id: "close", label: "Close: expected activity", tone: "close" },
          { id: "work", label: "Keep working: search related events", tone: "contain" },
          { id: "escalate", label: "Escalate now", tone: "escalate" },
        ],
        alerts: [
          { id: "q1", time: "09:10", severity: "Medium", rule: "Reconnaissance command: net group", entity: "ALD-BRS-IT02",
            fields: [{ k: "user", v: "adm-o.reid" }, { k: "host role", v: "IT admin workstation" }, { k: "account type", v: "Named admin, working hours" }, { k: "ticket", v: "CHG-4471 quarterly access review" }],
            context: "The admin's own workstation, during the working day, with a change ticket that says exactly this.", answer: "close", why: "Host, user and ticket all fit. Record CHG-4471 in the note and close it." },
          { id: "q2", time: "09:12", severity: "Medium", rule: "Reconnaissance command: net group", entity: "ALD-DC01",
            fields: [{ k: "user", v: "svc-printq" }, { k: "host role", v: "Domain controller" }, { k: "account type", v: "Service account" }, { k: "prior history", v: "No command history on any host" }],
            context: "The same rule and severity, but on a domain controller, from a service account that only manages print queues.", answer: "escalate", why: "Unusual activity on a domain controller weighs far more than the same activity on a workstation, and a service account has no reason to run commands there." },
          { id: "q3", time: "09:40", severity: "Low", rule: "Outbound connection to a new destination", entity: "ALD-PER-WS12",
            fields: [{ k: "destination", v: "198.51.100.23" }, { k: "internal or external", v: "External" }, { k: "reputation", v: "No reports" }, { k: "first seen", v: "Today, this host only" }],
            context: "Threat intelligence such as VirusTotal and AbuseIPDB has nothing on this address. Nobody else here has connected to it.", answer: "work", why: "No reports is not the same as clean. Run Step 4: all events from this host, this user and this address, plus other alerts on them." },
          { id: "q4", time: "10:03", severity: "Medium", rule: "User sign-in from a new IP address", entity: "h.moss",
            fields: [{ k: "source", v: "10.44.9.18" }, { k: "internal or external", v: "Internal" }, { k: "device owner", v: "ALD-PER-WS31, h.moss's own PC" }, { k: "DHCP", v: "Lease renewed 09:58" }],
            context: "If an address is internal, ask which device owns it. This one is the user's own PC, on a fresh lease five minutes before the sign-in.", answer: "close", why: "New address, same device. The rule saw a number change. Nothing about the user or the host did." },
        ],
      },
      {
        kind: "hunt",
        title: "The SPL Ladder: Where the Account Went",
        prompt: "Alert, Tuesday 03:40 UTC: admin account on a new host, adm-o.reid. The inventory says that admin works from ALD-BRS-IT02. Run Steps 4 and 5 in SPL (Search Processing Language, Splunk's query language), one line at a time, with the time picker set 24 hours either side. Every result is what that line really returns.",
        language: "SPL",
        console: "Search",
        start: "index=wineventlog EventCode=4624",
        goal: "the logon paths that need a second look",
        tables: [
          {
            name: "index=wineventlog EventCode=4624",
            note: "Successful logons. _time follows your user time zone setting, here UTC.",
            columns: ["_time", "host", "EventCode", "Logon_Type", "Account_Name", "Source_Network_Address", "Authentication_Package"],
            rows: [
              ["2026-10-12 09:14:02", "ALD-BRS-FS01", "4624", "3", "adm-o.reid", "10.40.1.12", "Kerberos"],
              ["2026-10-12 09:14:40", "ALD-BRS-FS01", "4624", "3", "adm-o.reid", "10.40.1.12", "Kerberos"],
              ["2026-10-12 09:31:17", "ALD-CRM-01", "4624", "3", "adm-o.reid", "10.40.1.12", "Kerberos"],
              ["2026-10-12 10:02:11", "ALD-BRS-PRN1", "4624", "3", "adm-o.reid", "10.40.1.12", "NTLM"],
              ["2026-10-12 10:02:13", "ALD-BRS-PRN1", "4624", "3", "adm-o.reid", "10.40.1.12", "NTLM"],
              ["2026-10-12 11:20:44", "ALD-BRS-IT02", "4624", "2", "adm-o.reid", "127.0.0.1", "Negotiate"],
              ["2026-10-12 14:05:09", "ALD-CRM-01", "4624", "10", "adm-o.reid", "10.40.1.12", "Negotiate"],
              ["2026-10-12 15:40:26", "ALD-BRS-FS01", "4624", "3", "o.reid", "10.40.1.30", "Kerberos"],
              ["2026-10-12 15:41:02", "ALD-BRS-FS01", "4624", "3", "o.reid", "10.40.1.30", "Kerberos"],
              ["2026-10-13 03:31:52", "ALD-PER-FS01", "4624", "3", "ADM-O.REID", "10.42.7.31", "NTLM"],
              ["2026-10-13 03:32:05", "ALD-PER-FS01", "4624", "3", "ADM-O.REID", "10.42.7.31", "NTLM"],
              ["2026-10-13 03:36:40", "ALD-PER-FS01", "4624", "3", "ADM-O.REID", "10.42.7.31", "NTLM"],
              ["2026-10-13 04:02:18", "ALD-CRM-01", "4624", "3", "svc-crmsync", "10.40.2.22", "Kerberos"],
            ],
          },
          {
            name: "asset_inventory.csv",
            note: "Lookup file: which device owns each internal address.",
            columns: ["ip", "nt_host", "role"],
            rows: [
              ["10.40.1.12", "ALD-BRS-IT02", "IT admin workstation"],
              ["10.40.1.30", "ALD-BRS-WS22", "Office PC, Bristol"],
              ["10.42.7.31", "ALD-HFX-WS07", "Reception PC, Halifax"],
              ["10.40.1.50", "ALD-BRS-FS01", "File server, Bristol"],
              ["10.40.1.60", "ALD-BRS-PRN1", "Print server, Server 2012"],
              ["10.40.2.20", "ALD-CRM-01", "CRM server"],
              ["10.40.2.22", "ALD-CRM-02", "CRM sync server"],
              ["10.44.1.50", "ALD-PER-FS01", "File server, Perth"],
            ],
          },
          {
            name: "index=wineventlog EventCode=7045",
            note: "System log: a new service was installed on a host.",
            columns: ["_time", "host", "EventCode", "Service_Name", "Service_File_Name", "Service_Account"],
            rows: [
              ["2026-10-12 22:15:03", "ALD-BRS-FS01", "7045", "BackupAgentUpdater", "C:\\Program Files\\BackupAgent\\updater.exe", "LocalSystem"],
            ],
          },
        ],
        rungs: [
          {
            id: "account", ask: "Line 2: keep this account, however Windows spelled it.",
            choices: [
              { id: "a", text: '| where Account_Name="adm-o.reid"', why: "Seven rows, and the three newest are gone. where compares case-sensitively, and Tuesday's logons are in capitals.", apply: { op: "where", col: "Account_Name", test: "eq", value: "adm-o.reid" } },
              { id: "b", text: "| search Account_Name=*reid*", why: "Twelve rows: the wildcard also pulled o.reid, the same person's everyday account. A partial match brings the neighbours along.", apply: { op: "where", col: "Account_Name", test: "has", value: "reid" } },
              { id: "c", text: "| search Account_Name=adm-o.reid", right: true, why: "Ten rows. search ignores case in field values, so every spelling of this one account is in.", apply: { op: "where", col: "Account_Name", test: "ieq", value: "adm-o.reid" } },
            ],
          },
          {
            id: "type", ask: "Line 3: Step 5 looks for movement between machines. Which logon type is that?",
            choices: [
              { id: "a", text: "| search Logon_Type=2", why: "One row: Type 2 is someone at the keyboard. That is the admin at their own PC, and nobody moved anywhere.", apply: { op: "where", col: "Logon_Type", test: "eq", value: "2" } },
              { id: "b", text: "| search Logon_Type=3", right: true, why: "Eight rows. Type 3 is a network logon, the mark a remote connection leaves on the target.", apply: { op: "where", col: "Logon_Type", test: "eq", value: "3" } },
              { id: "c", text: "| search Logon_Type=10", why: "One row: Type 10 is a Remote Desktop session. That is a real way to move, but it misses file shares, PsExec and WMI, which land as Type 3.", apply: { op: "where", col: "Logon_Type", test: "eq", value: "10" } },
            ],
          },
          {
            id: "owner", ask: "Line 4: an internal address means nothing yet. Which device owns each source?",
            choices: [
              { id: "a", text: "| table host Source_Network_Address", why: "Honest, but still a bare address. 10.42.7.31 tells a reader nothing until the inventory names it.", apply: { op: "project", cols: ["host", "Source_Network_Address"] } },
              { id: "b", text: "| lookup asset_inventory.csv nt_host AS host OUTPUT ip role", why: "That describes the machine that received the logon, which host already told you. The question is where each logon came from.", apply: { op: "join", table: "asset_inventory.csv", left: "host", right: "nt_host" } },
              { id: "c", text: "| lookup asset_inventory.csv ip AS Source_Network_Address OUTPUT nt_host role", right: true, why: "Every source address now has a name and a role. That is Step 3 inside the search: if an IP is internal, find out which device owns it.", apply: { op: "join", table: "asset_inventory.csv", left: "Source_Network_Address", right: "ip" } },
            ],
          },
          {
            id: "shape", ask: "Line 5: eight rows is a list. Show who logged on to what, how, and how often.",
            choices: [
              { id: "a", text: "| stats count by nt_host role host Authentication_Package", right: true, why: "Four rows, one per path. A shape is easier to read than a list: three paths start at the admin's PC, and one starts somewhere else.", apply: { op: "summarize", by: ["nt_host", "role", "host", "Authentication_Package"], as: "count" } },
              { id: "b", text: "| stats count by Account_Name", why: "Two rows for one person: the two spellings counted apart, and the paths you came for are gone. stats groups case-sensitively.", apply: { op: "summarize", by: ["Account_Name"], as: "count" } },
              { id: "c", text: "| table _time host nt_host", why: "Still eight rows. table chooses columns, and it groups nothing.", apply: { op: "project", cols: ["_time", "host", "nt_host"] } },
            ],
          },
          {
            id: "package", ask: "Line 6: in an Active Directory domain Kerberos is the default. Keep the paths that used something else.",
            choices: [
              { id: "a", text: "| search nt_host=ALD-BRS-IT02", why: "Three rows, all from the admin's own PC. That is the baseline, and you are looking for what breaks it.", apply: { op: "where", col: "nt_host", test: "ieq", value: "ALD-BRS-IT02" } },
              { id: "b", text: "| search Authentication_Package=Kerberos", why: "The opposite: these are the expected logons.", apply: { op: "where", col: "Authentication_Package", test: "ieq", value: "Kerberos" } },
              { id: "c", text: "| search Authentication_Package=NTLM", right: true, why: "Two rows. NTLM (NT LAN Manager) is the older Windows authentication protocol, and logging on with a stolen hash produces it. So do ordinary things, as these two rows are about to show.", apply: { op: "where", col: "Authentication_Package", test: "ieq", value: "NTLM" } },
            ],
          },
          {
            id: "ticket", ask: "Line 7: the ticket needs the source, its role, the target, the package and the count.",
            choices: [
              { id: "a", text: "| table Source_Network_Address host count", why: "Source_Network_Address did not survive stats, which keeps only its by fields and the count. There is nothing left to show.", apply: { op: "project", cols: ["Source_Network_Address", "host", "count"] } },
              { id: "b", text: "| table nt_host role host Authentication_Package count", right: true, why: "Two rows a reader can judge without opening a log. The count column is what stats made.", apply: { op: "project", cols: ["nt_host", "role", "host", "Authentication_Package", "count"] } },
              { id: "c", text: "| table nt_host host", why: "Right rows, too little in them. The ticket can't say how those logons were made or how many there were.", apply: { op: "project", cols: ["nt_host", "host"] } },
            ],
          },
        ],
        expect: 2,
        lesson: "Both rows used NTLM, and they mean different things. The Server 2012 print server, reached by IP address, is an ordinary cause. A Halifax reception PC logging on as an admin to a Perth file server is not. Even so, NTLM alone proves nothing: it is a signal to corroborate. The next search stays on that target: EventCode=7045 for a service installed there, then admin shares and PSEXESVC.exe or wmiprvse.exe starting processes. In SPL, search ignores case and where doesn't, and stats keeps only what it counts and groups by.",
      },
      {
        kind: "sort",
        title: "Moving or Leaving?",
        prompt: "Step 5 of the SIEM workflow looks for lateral movement, an intruder moving between machines. Step 6 looks for exfiltration, data leaving. Mixing them up sends the response the wrong way. Sort this week's search results, and remember that some are neither.",
        buckets: [
          { id: "moving", label: "Moving: lateral movement" },
          { id: "leaving", label: "Leaving: exfiltration" },
          { id: "neither", label: "Neither, on this evidence" },
        ],
        items: [
          { id: "s1", text: "wmiprvse.exe starts cmd.exe on ALD-PER-FS01", bucket: "moving", why: "WMI (Windows Management Instrumentation) running a command remotely leaves wmiprvse.exe as the parent on the target." },
          { id: "s2", text: "PSEXESVC.exe runs under services.exe on a Perth server", bucket: "moving", why: "PsExec copies this binary to the target and installs it as a service, so the System log gains a 7045 entry too." },
          { id: "s3", text: "A reception PC opens \\\\ALD-BRS-FS01\\ADMIN$", bucket: "moving", why: "Admin shares such as ADMIN$ and C$ are how tools get pushed to another machine, and reception has no use for them." },
          { id: "s4", text: "One admin account, Type 3 logons on four servers in ten minutes", bucket: "moving", why: "Network logons from a compromised account across several hosts are the plainest sign of lateral movement." },
          { id: "s5", text: "rar.exe a -hp legacy.rar on the Legacy share", bucket: "leaving", why: "Compressing a sensitive directory, with a password here, is how data gets packed to go. Nothing has moved between machines." },
          { id: "s6", text: "ALD-CRM-01 opens a connection to a Mega upload address", bucket: "leaving", why: "A file-sharing service reached from a sensitive host is an exfiltration indicator. Mega and Dropbox are the usual names." },
          { id: "s7", text: "New-InboxRule forwards a bereavement mailbox to a free webmail address", bucket: "leaving", why: "A forwarding rule, seen in the O365 audit log, sends the data out quietly for as long as it stays." },
          { id: "s8", text: "A file server that sends 40 MB a day sends 2.1 GB overnight", bucket: "leaving", why: "An unusual outbound byte count in the firewall log is the classic sign. Compare it with that host's normal day." },
          { id: "s9", text: "Kerberos Type 3 logon by a fundraiser to the Fundraising share", bucket: "neither", why: "The right user, the right share and the default protocol. A network logon alone is not movement." },
          { id: "s10", text: "The nightly backup copies 30 GB to the backup server", bucket: "neither", why: "Large, but internal, scheduled and to a known destination. Volume means something only against its baseline." },
          { id: "s11", text: "NTLM logon to an old print server addressed by IP", bucket: "neither", why: "Reaching a server by IP address, or an older system, produces NTLM. Note it, and look for something that corroborates it." },
        ],
      },
    ],
    "inv-method-q5": [
      {
        kind: "hotspot",
        title: "Mark Up the Draft Ticket",
        prompt: "A night analyst left this draft. Rafe wants it fit for a reader who wasn't there. Flag every line that would fail that reader. Tapping a sound line tells you why it stays.",
        artifact: "Case 2291 · draft",
        parts: [
          { id: "title", style: "subject", text: "Case 2291: Legacy records exported from the donor CRM", flag: false, note: "A clear title. The same fields sit in TheHive, in ServiceNow's Security Operations module, or in an adapted Jira project." },
          { id: "summary", style: "body", text: "Summary: a staff login exported legacy records, and a second host called the same external address.", flag: false, note: "One paragraph on what happened. A senior reader can stop here and know the case." },
          { id: "timeline", style: "body", text: "Timeline: 03:48 export, 10:21 web request, 23:14 mail delivered.", flag: true, note: "Three systems' clocks, no zone, no source, and the order is wrong as a result. A timeline is in UTC, sorted, with the source of each line." },
          { id: "evidence", style: "body", text: "Evidence: see the three images pasted below.", flag: true, note: "A picture of a result can't be re-run, filtered or widened. The next analyst needs something they can open and reproduce." },
          { id: "assets", style: "body", text: "Affected assets: some laptops in Perth.", flag: true, note: "Name every host, user and IP. 'Some laptops' can't be scoped, contained or checked." },
          { id: "chain", style: "body", text: "Chain of events: phishing mail, a callback from the laptop, the CRM export, then data out through the firewall.", flag: false, note: "A narrative of how the attack unfolded, which is different from the timeline's list of events." },
          { id: "conclusion", style: "body", text: "Conclusion: looks bad.", flag: true, note: "A conclusion states true positive or false positive, a severity and the MITRE ATT&CK techniques used." },
          { id: "actions", style: "body", text: "Actions taken: ALD-PER-LT31 isolated 15:12 UTC. l.tran's password reset, sessions revoked.", flag: false, note: "What was done, to what, and when. The next shift won't repeat it or assume it." },
          { id: "recs", style: "body", text: "Recommendations: block HTML attachments at the gateway, set every log source to UTC.", flag: false, note: "What should improve so this doesn't recur. This is how a case pays for itself." },
          { id: "later", style: "meta", text: "Note to self: tidy this up at the end of the shift.", flag: true, note: "Document as you go, not at the end. Memory fades and logs don't." },
        ],
        finish: "This ticket can now be checked by someone who wasn't there.",
      },
    ],
    // ── The graded record ──
    "inv-method-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of an Expected Logon",
        prompt: "This logon is fine, and it reached Rafe's desk only because the rule is broad. Read it field by field anyway, against the one line the asset inventory holds for this account. That comparison is the skill.",
        source: "Windows Security · 4624 · ALD-CRM-01",
        fields: [
          { key: "event.code", value: "4624", label: "What", note: "A logon succeeded. Success says nothing yet about whether it should have." },
          { key: "winlog.event_data.TargetUserName", value: "svc-crmsync", label: "As whom", note: "Inventory: svc-crmsync syncs donor records from ALD-CRM-02 (10.40.2.22) to ALD-CRM-01 and authenticates from nowhere else. Hold every field below against that line." },
          { key: "winlog.event_data.LogonType", value: "3", label: "How it arrived", note: "A network logon, which is how any account normally reaches a server. Type 3 alone is no deviation." },
          { key: "winlog.event_data.WorkstationName", value: "-", label: "Client name", note: "The client reports its name on NTLM logons, and a Kerberos network logon normally leaves this as \"-\", so nothing is wrong here. When it is filled in, it shows where the authentication came from, and you hold it against the inventory." },
          { key: "winlog.event_data.IpAddress", value: "10.40.2.22", label: "From address", note: "The address the server saw. 10.40.2.22 is ALD-CRM-02 in the inventory, so nothing is out of pattern. When you need to know what a source machine has been doing, this is the value you take to the SIEM." },
          { key: "winlog.event_data.AuthenticationPackageName", value: "Kerberos", label: "Protocol", note: "The default in an Active Directory domain. NTLM here would deserve a look, because Pass-the-Hash (logging on with a stolen hash) produces it. A server reached by IP or an older system does too, so weigh it with other evidence." },
          { key: "winlog.event_data.ElevatedToken", value: "%%1843", label: "Elevated?", note: "%%1842 means Yes and %%1843 means No. Read it against the account's job: a high-privilege account getting an elevated token is expected." },
        ],
        summary: "A 4624 only tells you a logon happened. The verdict comes from comparing the record with what you know about the account: who it is, where it should come from, how it should arrive, and how it authenticated. One field out of pattern is a lead, and the next step is to take that lead to another source.",
      },
    ],
  },
};
