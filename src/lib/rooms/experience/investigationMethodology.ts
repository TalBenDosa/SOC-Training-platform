import type { RoomExperience } from "./types";

// "Operation Loose Thread" for the "investigation-methodology" room.
// Script: docs/campaign/61-investigation-methodology.md. Practical-missions pilot:
// research/rooms-practical-tasks/G7-ir-process.md, section 61.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// TASK ORDER: r1, q1, m1 | r2, q3, m2a | r3, m2b, m3 | m4 (boss). The case notebook runs
// as five missions (src/lib/missions/rooms/looseThread.ts, dataset "loose-thread"): the
// lure's indicators, the hypothesis board in two halves (seven hops, each question picks
// its source and its fact picks the next), one UTC timeline from four clocks, then scope
// and a slotted finding. q2, q5, la1, flag1 and q4 retired (the missions do that work);
// q1 (collect before rollover) and q3 (which source is UTC by format) stay as key checks.
//
// Arcade labs left with the redesign (deduce, the two sorts, match, pathway). Tool labs stay
// as practice on the readings; the hotspot (was q5) and the anatomy (was la1) moved onto r3.
// Practice data differs from the graded case: the labs use St Aldric's older ALD- hosts,
// l.tran, ALD-PER-LT31, 203.0.113.58, 10.40.x/10.42.x/10.44.x and October dates; the graded
// case is SAH- hosts, m.oduya, SAH-BRS-LT14, 203.0.113.164, 10.10.x and 14 April 2026. The
// UTC sequence lab's export is 860 records and 610 MB, never the graded 2,140 records and
// 1.4 GB. The rollover drill is a VPN buffer and laptop memory, never one server's Security
// log (q1); no lab merges an EVTX, an IIS log and Sentinel results, and no lab uses UTC+2 (q3).

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
  mission: "Pull the attacker's indicators out of the lure, then follow them hop by hop: pick the source for each question, write the query, pin the row. Rebuild the morning on one UTC clock, state the scope and write a finding anyone can check.",
  estimate: "~75 min",
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
      topic: "Detective mindset · the six phases · collect before it is gone · indicators from the lure",
      tagline: "What would have to be true?",
      building: "reception",
      taskIds: ["inv-method-r1", "inv-method-q1", "inv-method-m1"],
    },
    {
      id: "pivot",
      label: "Pivot and Timeline",
      topic: "Evidence pivoting · where to look for each question · mail to click to process",
      tagline: "Each finding picks the next source",
      building: "lab",
      taskIds: ["inv-method-r2", "inv-method-q3", "inv-method-m2a"],
    },
    {
      id: "casefile",
      label: "SIEM and Case File",
      topic: "IP to hosts · the application's own audit · bytes out · one timeline in UTC",
      tagline: "Can someone else check your work?",
      building: "office",
      taskIds: ["inv-method-r3", "inv-method-m2b", "inv-method-m3"],
    },
    {
      id: "logon",
      label: "Tie It Off",
      topic: "Scope with edges · a five-part finding · gaps stated, not hidden",
      tagline: "Someone reads this in a year",
      building: "ticket",
      taskIds: ["inv-method-m4"],
      boss: true,
    },
  ],
  personas: {
    "inv-method-q1": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "The case is scoped. Tell me your next move." },
    "inv-method-m1": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "The attacker's side of the mail goes in the notebook. Only that side." },
    "inv-method-q3": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "Three sources, one timeline. Which one worries you?" },
    "inv-method-m2a": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "One question, one source, one pinned row. Then the next." },
    "inv-method-m2b": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "One laptop or ten? The address will tell us." },
    "inv-method-m3": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "As printed, the data leaves before the mail arrives. Fix the clocks." },
    "inv-method-m4": { name: "Rafe Nakagawa", role: "Senior Investigator", line: "Every claim with the source that proves it." },
  },
  briefings: {
    // ── Reading 1 has no lab: the missions open the case right after its question. ──
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
    // ── Reading 2: time zones and timelines (practice for q3 and the timeline mission) ──
    "inv-method-r2": [
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
          { id: "fw", text: "Firewall, Halifax (UTC-3): Mon 12 Oct 23:58:31. 610 MB out to 203.0.113.58", note: "02:58:31 UTC, Tuesday. Add 3 hours and the date rolls over." },
          { id: "crm", text: "CRM application log, Bristol (UTC+1): Tue 13 Oct 03:48:12. l.tran exports 860 records", note: "02:48:12 UTC. Subtract 1 hour." },
          { id: "siem", text: "SIEM alert (UTC): Tue 13 Oct 03:20:00. Low: rare outbound destination", note: "03:20:00 UTC. The SIEM (Security Information and Event Management platform) is already in UTC." },
          { id: "proxy", text: "Web proxy, Perth (UTC+8): Tue 13 Oct 10:21:40. ALD-PER-LT31 opens giftaid-form.example", note: "02:21:40 UTC. Subtract 8 hours." },
          { id: "mail", text: "Mail gateway, Halifax (UTC-3): Mon 12 Oct 23:14:08. 'Gift Aid form' delivered to l.tran", note: "02:14:08 UTC, Tuesday. Add 3 hours and the date rolls over." },
          { id: "edr", text: "EDR (UTC): Tue 13 Oct 02:23:05. rundll32.exe starts on ALD-PER-LT31", note: "02:23:05 UTC. Already in UTC." },
        ],
        order: ["mail", "proxy", "edr", "crm", "fw", "siem"],
        doneNote: "Sorted by the printed clocks, the data leaves before the malware runs and the click comes last: a story that never happened. In UTC it reads straight: mail, click 7 minutes later, code running, export, and 610 MB gone 21 minutes before the alert fired. That is what a timeline answers: when the first foothold was, how long until the next move, whether the data left before the alert, and whether they came back. So work in UTC, search 24 to 48 hours either side of the trigger across the same user, host and IP, and tag every line with its source. Sentinel's Investigation Graph and the MDE (Microsoft Defender for Endpoint) Timeline tab help, and a shared spreadsheet is enough for a small case.",
      },
    ],
    // ── Reading 3: SIEM workflow and case management (practice for the scope and the finding) ──
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
