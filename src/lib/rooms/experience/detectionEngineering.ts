import type { RoomExperience } from "./types";

// "Operation Signal and Noise" for the "detection-engineering" room.
// Script: docs/campaign/96-detection-engineering.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Cadenza Music Group (fictional), not the graded tasks' corp.com records.
// Mentor: Lior Danso, Detection Lead.
// Signature, Coverage Is Not Quantity: the learner manages a detection backlog. A hunt in SPL
// measures which ATT&CK techniques have rules that ever fired, a spotdiff compares a rule before
// and after a bypass-resistant rewrite, and a duel plays an attacker's evasions against the
// detection logic that survives them. Room 73 ships one use case; this room runs the program.
// Game mix: duel + hunt + spotdiff.
//
// TASK ORDER CHANGED. The room lists all four readings first, then the graded tasks, so it cannot
// be cut into stations. New order, for the integrator:
//   deteng-r1, deteng-q1 | deteng-r2, deteng-q3 | deteng-r3, deteng-r4, deteng-m1, deteng-q2 |
//   deteng-la1, deteng-flag1, deteng-queryfill1
// Readings stay in order 1 to 4, so every "Reading N" reference holds: q2 still follows Reading 4
// and the query fill still follows Reading 2. flag1 still follows la1 and names its alert by rule
// name, with no "Log Analysis N" number to break.
//
// Lab data differs from the graded tasks: the precision sheet uses other rates and volumes, and
// its worked example is a parcel scanner (q1); the heatmap path is T1133, T1003.001, T1021.002,
// T1039, T1560.001 and T1567.002, never the three empty techniques of q3; the Sigma anatomy is a
// schtasks rule, never encoded PowerShell (q2, r4 checkpoint), and it never moves a rule to a
// firewall logsource; the ID anatomy is T1021.002, never T1110.003 (la1); the spread sheet shows
// 50, 1 and 3 tries per account, never the alert's 2 (la1); the containment drill is a leaked API
// token, never a spray or an account (la1); the status code anatomy is a retired scan job that
// returns 0xC0000064, and the graded code only appears in its note as data, never asked (flag1);
// the stats drill is shares per account on Event 5140, never accounts per source on 4625
// (query fill), and dc() appears in the primer and the sheet, never as an answer to type.

/** The spotdiff renders in HTML, which drops plain leading spaces, and YAML needs its indent. */
const y = (depth: number, line: string) => "\u00A0".repeat(depth * 2) + line;

export const DETECTION_ENGINEERING: RoomExperience = {
  roomId: "detection-engineering",
  codename: "Operation Signal and Noise",
  theme: "signalnoise",
  handler: { name: "Lior Danso", role: "Detection Lead, Cadenza Music Group" },
  briefing: [
    "Cadenza Music Group. Three labels, a publishing arm, 620 staff, and a catalogue of master recordings that is the whole business.",
    "The SIEM (Security Information and Event Management system, where every log lands) holds 1,240 detection rules. The quarterly report calls that 81% coverage of MITRE ATT&CK, the public catalogue of attacker techniques.",
    "Last Friday an unreleased album turned up on a leak forum. The intruder had been inside for 19 days, and not one rule fired.",
    "Lior Danso, Detection Lead, has inherited the backlog and one question from the board: how much of that coverage is real? Measure it, rewrite what can be dodged, and be ready when a rule finally fires.",
  ],
  mission: "Work out what noisy rules really cost, sort what the vendor pack can't know, measure which techniques have rules that ever fired, walk the intruder's path across the heatmap, rewrite a rule so it can't be dodged, beat the red team's evasions, then read the alert that fires.",
  estimate: "~55 min",
  look: { primary: "#f0abfc", secondary: "#67e8f9", warn: "#fb5607" },
  scene: "facilitysignalnoise",
  layout: "facility",
  stations: [
    {
      id: "backlog",
      label: "The Backlog",
      topic: "What detection engineering is · vendor default rules · precision · alert fatigue",
      tagline: "1,240 rules. How many earn their place?",
      building: "control",
      taskIds: ["deteng-r1", "deteng-q1"],
    },
    {
      id: "heatmap",
      label: "The Heatmap",
      topic: "Detection logic types · Sigma · ATT&CK tactics, techniques and sub-techniques · coverage",
      tagline: "A green cell is only a tag",
      building: "lab",
      taskIds: ["deteng-r2", "deteng-q3"],
    },
    {
      id: "rewrite",
      label: "The Rewrite",
      topic: "The rule lifecycle · a Sigma rule field by field · logsource · rules that survive evasion",
      tagline: "Make it hard to dodge",
      building: "office",
      taskIds: ["deteng-r3", "deteng-r4", "deteng-m1", "deteng-q2"],
    },
    {
      id: "firstfire",
      label: "First Fire",
      topic: "Reading a correlation alert · failure spread · logon status codes · writing the SPL by hand",
      tagline: "It fired. Now read it.",
      building: "ticket",
      taskIds: ["deteng-la1", "deteng-flag1", "deteng-queryfill1"],
      boss: true,
    },
  ],
  personas: {
    "deteng-q1": { name: "Lior Danso", role: "Detection Lead", line: "Before anyone argues about this rule, do the arithmetic." },
    "deteng-q3": { name: "Lior Danso", role: "Detection Lead", line: "The heatmap is on the wall. Tell me what I'm looking at." },
    "deteng-m1": { name: "Lior Danso", role: "Detection Lead", line: "Name the parts before you touch the rule." },
    "deteng-q2": { name: "Lior Danso", role: "Detection Lead", line: "This shipped on Friday. Walk me through what happens next." },
    "deteng-la1": { name: "Lior Danso", role: "Detection Lead", line: "This one fired. Read all of it." },
    "deteng-flag1": { name: "Lior Danso", role: "Detection Lead", line: "One value, exactly as it's written." },
    "deteng-queryfill1": { name: "Lior Danso", role: "Detection Lead", line: "No converter this time. Write the logic yourself." },
  },
  briefings: {
    // ── Reading 1: what a rule costs, and what a vendor pack can't know ──
    "deteng-r1": [
      {
        kind: "worksheet",
        title: "What Does a Noisy Rule Cost?",
        prompt: "Five rules from the top of Lior's backlog, with last month's triage numbers. Work out what each one costs the shift. Precision is the share of a rule's alerts that were real.",
        caption: "Backlog · alert volume and precision · last 30 days",
        columns: ["Rule", "Level", "Alerts a day", "Precision"],
        rows: [
          ["CDZ-0114 Cmd With Long Arguments", "low", "300", "92%"],
          ["CDZ-0113 Cmd From Temp Folder", "medium", "60", "90%"],
          ["CDZ-0403 Task Run As System", "medium", "40", "70%"],
          ["CDZ-0801 New Admin On Royalty Server", "high", "50", "98%"],
          ["CDZ-0802 Service Account Interactive Logon", "high", "100", "99.5%"],
        ],
        questions: [
          { id: "one", q: "How many false positives a day does CDZ-0114 hand the shift?", hint: "Alerts a day times the share that wasn't real.", answer: ["24"], why: "300 alerts at 92% precision leaves 8% that weren't real: 24 a day from one low-level rule." },
          { id: "all", q: "Add up all five rules. How many false positives a day is that?", hint: "24 + 6 + 12, then the two high-level rules.", answer: ["43.5", "44"], why: "24 + 6 + 12 + 1 + 0.5 = 43.5. No rule on this sheet looks terrible alone. The shift lives with the total, and Cadenza has 1,240 rules." },
          { id: "bar", q: "Which of the two high-level rules meets the usual bar for high severity?", hint: "The bar is in the primer.", answer: ["CDZ-0802", "0802"], why: "CDZ-0802 sits at 99.5%. CDZ-0801 fires half as often and still misses the bar at 98%: volume and precision are separate measures." },
        ],
        primer: {
          title: "Precision, in One Sum",
          fold: true,
          points: [
            "**Precision** is true positives divided by all alerts: TP / (TP + FP). A TP is a real attack. An FP is an alert that wasn't one.",
            "False positives a day = alerts a day × (1 − precision).",
            "Analysts live with the sum across every rule, so a tired shift starts treating alerts as noise. That is **alert fatigue**.",
            "For high and critical rules, teams usually want precision above **99%**.",
          ],
          example: {
            label: "Worked example: a parcel scanner",
            lines: [
              "A depot scanner flags 400 parcels a day, and 97% of the flags are right.",
              "`400 × 0.03 = 12` parcels opened for nothing, every day.",
              "Ten scanners like it: 120.",
            ],
          },
        },
      },
      {
        kind: "sort",
        title: "What Can't the Vendor Pack Know?",
        prompt: "The SIEM shipped with a vendor rule pack, and most of the backlog started there. Sort these the way Lior would: keep it as it came, tune it for Cadenza, or write something the pack could never have included.",
        buckets: [
          { id: "keep", label: "Keep as shipped" },
          { id: "tune", label: "Tune for Cadenza" },
          { id: "write", label: "Write our own" },
        ],
        items: [
          { id: "s1", text: "Pack rule: sign-in outside 08:00 to 18:00. Studio engineers book sessions until 04:00.", bucket: "tune", why: "The logic is sound, and the hours are somebody else's. It needs Cadenza's working pattern." },
          { id: "s2", text: "Pack rule: remote admin tool launched. IT pushes mixing-desk updates with that tool every Tuesday.", bucket: "tune", why: "Keep the rule and carve out that one job, narrowly, with an owner and a reason written down." },
          { id: "s3", text: "Pack rule: service account outside the svc_ naming pattern. Cadenza's service accounts all start ca_.", bucket: "tune", why: "Every Cadenza service account trips it. The rule needs the local convention." },
          { id: "s4", text: "The Masters vault server should never talk to the internet. No pack rule knows which server that is.", bucket: "write", why: "A vendor can't know your crown jewels. Only Cadenza can name that server and say what normal is for it." },
          { id: "s5", text: "Royalty exports should only ever be run by the finance bot. The pack has never heard of the royalty system.", bucket: "write", why: "An in-house system with an in-house rule of who may do what. Nobody else can write this one." },
          { id: "s6", text: "Pack rule: Windows Security event log cleared. Fires a few times a year, and each one has needed explaining.", bucket: "keep", why: "It means the same thing in any company, and it is rare and worth a look." },
        ],
        primer: {
          title: "Who a Vendor Pack Is Written For",
          fold: true,
          points: [
            "A vendor writes one pack for every customer at once. It has never seen your staff, your servers or your scripts.",
            "Some rules mean the same thing anywhere. Others carry assumptions about hours, names and tools that are true somewhere else.",
            "A rule about **your** most valuable system can only come from you.",
          ],
          example: {
            label: "Worked example: a bakery's alarm",
            lines: [
              "Installer's rule: door opened at 02:00. In a bakery, that's the morning shift. Tune it.",
              "Installer's rule: glass broken. True anywhere. Keep it.",
              "The flour store's back hatch: the installer never knew it existed. Add a sensor.",
            ],
          },
        },
      },
    ],
    // ── Reading 2: logic types, Sigma and ATT&CK, then the measurement ──
    "deteng-r2": [
      {
        kind: "sort",
        title: "Which Kind of Logic Is This?",
        prompt: "The inventory has no column for how a rule decides, and Lior needs one before the rewrite starts. Sort these rules by their logic.",
        buckets: [
          { id: "sig", label: "Signature" },
          { id: "thr", label: "Threshold" },
          { id: "ano", label: "Anomaly" },
          { id: "cor", label: "Correlation" },
        ],
        items: [
          { id: "l1", text: "File hash equals a known wiper sample", bucket: "sig", why: "An exact match on one known bad value. Precise, and blind to the next build." },
          { id: "l2", text: "Process name is rclone.exe", bucket: "sig", why: "Still an exact match on a known pattern, even though it isn't a hash." },
          { id: "l3", text: "More than 500 MB uploaded by one user in 5 minutes", bucket: "thr", why: "A count against a fixed limit in a time window." },
          { id: "l4", text: "One process renames more than 30 files in a minute", bucket: "thr", why: "A count again. The limit has to be set for your own estate." },
          { id: "l5", text: "This account's downloads today are ten times its own 30-day average", bucket: "ano", why: "No fixed number: the rule compares the account with its own learned normal." },
          { id: "l6", text: "A sign-in from a country this user has never used", bucket: "ano", why: "Deviation from a baseline, which needs a training period to exist." },
          { id: "l7", text: "VPN sign-in, then a read of the Masters share, then an archive in Temp: same account, 30 minutes", bucket: "cor", why: "Three events from different sources, joined into one detection." },
          { id: "l8", text: "An endpoint alert on a laptop and a firewall block for the same host within 10 minutes", bucket: "cor", why: "Two sources agreeing about one host." },
        ],
        primer: {
          title: "Four Ways a Rule Can Decide",
          fold: true,
          points: [
            "**Signature:** an exact match on a known bad pattern.",
            "**Threshold:** a count that passes a fixed limit in a time window.",
            "**Anomaly:** a change from a learned baseline of normal.",
            "**Correlation:** several events, often from different sources, joined into one detection.",
          ],
          example: {
            label: "Worked example: a shop's till",
            lines: [
              "Card number on the stolen list: signature.",
              "More than five refunds in an hour: threshold.",
              "Twice this cashier's usual refunds: anomaly.",
              "A refund, then the till drawer forced, same shift: correlation.",
            ],
          },
        },
      },
      {
        kind: "anatomy",
        title: "Anatomy of an Inventory Row",
        prompt: "One rule's row from Cadenza's detection inventory. Every coverage number is built from rows like this, so read what each field really says.",
        source: "detection_inventory.csv · one rule",
        fields: [
          { key: "rule_name", value: "CDZ-0232 Psexesvc Service Install", label: "The rule" },
          { key: "tactic", value: "Lateral Movement (TA0008)", label: "Tactic", note: "The attacker's goal at this stage, and a column of the ATT&CK matrix. Enterprise ATT&CK v19 has 15 of them. Tactic IDs start TA." },
          { key: "parent_technique", value: "T1021 Remote Services", label: "Technique", note: "The method used to reach that goal, and a row in the column. Techniques carry a T-number." },
          { key: "technique", value: "T1021.002", label: "Sub-technique", note: "SMB/Windows Admin Shares, a more specific variant of the parent technique. The digits after the dot number the variants: T1021.001 is Remote Desktop Protocol under the same parent. This column holds the most specific ID the rule maps to." },
          { key: "scope", value: "masters", label: "Scope", note: "The part of the estate the rule protects. Lets a search pull one group of rules out of the 1,240." },
          { key: "sigma_source", value: "sigma/lateral/psexesvc_service.yml", label: "Stored as", note: "Sigma: a detection written in YAML, tied to no one SIEM's query language. This file is the only copy of the logic." },
          { key: "compiled_to", value: "splunk_spl, sentinel_kql", label: "Deployed as", note: "sigma-cli converts that one file for each target SIEM. Change the logic once, convert again, and every target follows." },
          { key: "heatmap_cell", value: "green", label: "On the heatmap", note: "Painted from the tag alone. The field records that a rule exists with this tag." },
        ],
        summary: "Read an ATT&CK ID from the outside in: the goal, the method, the variant. Sigma means one rule can be written once and shared across SIEMs and teams. And notice what a row doesn't say: nothing here records whether the rule has ever run on real data and raised an alert. The heatmap can't tell you that. The next query can.",
      },
      {
        kind: "hunt",
        title: "What Ever Fired?",
        prompt: "The report counts rules. Lior wants a harder number: which ATT&CK techniques have a live, tagged rule that has really raised an alert in the last 12 months? Start from the 14 rules on the path into the Masters vault and build the search one line at a time. Every result you see is what that line really returns.",
        language: "SPL",
        console: "Search",
        start: '| inputlookup detection_inventory.csv where scope="masters"',
        goal: "one row per ATT&CK technique with a rule that has really fired",
        tables: [
          {
            name: '| inputlookup detection_inventory.csv where scope="masters"',
            note: "One row per rule. technique is the ATT&CK tag the heatmap reads.",
            columns: ["rule_name", "technique", "scope", "status", "level"],
            rows: [
              ["CDZ-0112 Office Spawns Cmd", "T1059.003", "masters", "enabled", "high"],
              ["CDZ-0113 Cmd From Temp Folder", "T1059.003", "masters", "enabled", "medium"],
              ["CDZ-0114 Cmd With Long Arguments", "T1059.003", "masters", "enabled", "low"],
              ["CDZ-0115 Cmd Writes Run Key", "T1059.003", "masters", "enabled", "medium"],
              ["CDZ-0231 Admin Share Copy", "T1021.002", "masters", "enabled", "high"],
              ["CDZ-0232 Psexesvc Service Install", "T1021.002", "masters", "enabled", "high"],
              ["CDZ-0307 Lsass Read By Unknown Image", "T1003.001", "masters", "enabled", "high"],
              ["CDZ-0308 Comsvcs MiniDump", "T1003.001", "masters", "enabled", "critical"],
              ["CDZ-0402 Schtasks From User Folder", "T1053.005", "masters", "enabled", "medium"],
              ["CDZ-0403 Task Run As System", "T1053.005", "masters", "enabled", "medium"],
              ["CDZ-0518 Archive In Temp", "T1560.001", "masters", "enabled", "medium"],
              ["CDZ-0611 Cloud Upload Spike", "T1567.002", "masters", "disabled", "high"],
              ["CDZ-0612 Rclone Seen", "T1567.002", "masters", "enabled", "high"],
              ["CDZ-0720 Vault Share Mass Read", "", "masters", "enabled", "high"],
            ],
          },
          {
            name: "notable_fires_12mon.csv",
            note: "Scheduled summary of index=notable: one row for each rule that raised at least one alert on live data in 12 months. Purple-team runs are excluded.",
            columns: ["search_name", "mitre_technique", "fires", "last_fired"],
            rows: [
              ["CDZ-0112 Office Spawns Cmd", "T1059.003", "3", "2026-08-02"],
              ["CDZ-0113 Cmd From Temp Folder", "T1059.003", "21880", "2026-11-05"],
              ["CDZ-0114 Cmd With Long Arguments", "T1059.003", "109420", "2026-11-05"],
              ["CDZ-0115 Cmd Writes Run Key", "T1059.003", "640", "2026-11-03"],
              ["CDZ-0232 Psexesvc Service Install", "T1021.002", "6", "2026-06-19"],
              ["CDZ-0403 Task Run As System", "T1053.005", "14610", "2026-11-05"],
              ["CDZ-0611 Cloud Upload Spike", "T1567.002", "52", "2026-01-14"],
              ["CDZ-0720 Vault Share Mass Read", "", "4", "2026-05-27"],
            ],
          },
          {
            name: "rule_test_log.csv",
            note: "Purple-team test runs: which rule was exercised on purpose, and when.",
            columns: ["tested_rule", "tested_on", "result"],
            rows: [
              ["CDZ-0112 Office Spawns Cmd", "2026-03-11", "alerted"],
              ["CDZ-0308 Comsvcs MiniDump", "2026-03-11", "alerted"],
              ["CDZ-0518 Archive In Temp", "2026-03-11", "no alert"],
            ],
          },
        ],
        rungs: [
          {
            id: "live", ask: "Line 2: a switched-off rule covers nothing. Keep the rules that are running.",
            choices: [
              { id: "a", text: '| where status="Enabled"', why: "No rows. In SPL, where compares strings exactly, and the column holds lower-case values.", apply: { op: "where", col: "status", test: "eq", value: "Enabled" } },
              { id: "b", text: '| where status="enabled"', right: true, why: "13 rules left. CDZ-0611 is gone: it has a tag and a history, and it isn't running.", apply: { op: "where", col: "status", test: "eq", value: "enabled" } },
              { id: "c", text: '| where status="disabled"', why: "One row: the only rule that isn't running. That's the opposite of the question.", apply: { op: "where", col: "status", test: "eq", value: "disabled" } },
            ],
          },
          {
            id: "tagged", ask: "Line 3: the measure is per technique, so a rule needs an ATT&CK tag to count. Drop the ones without.",
            choices: [
              { id: "a", text: '| where level="high"', why: "Level says how urgent an alert is, and has nothing to do with the tag. The untagged rule is still here, and seven rules that belong are gone.", apply: { op: "where", col: "level", test: "eq", value: "high" } },
              { id: "b", text: '| where technique="T1059.003"', why: "One technique out of six: the one with the most rules on it. The question was about all of them.", apply: { op: "where", col: "technique", test: "eq", value: "T1059.003" } },
              { id: "c", text: '| where technique!=""', right: true, why: "12 rules. CDZ-0720 watches the vault and has fired, and without a tag no coverage measure can see it. Lior adds that to the backlog.", apply: { op: "where", col: "technique", test: "notin", value: [""] } },
            ],
          },
          {
            id: "join", ask: "Line 4: the inventory says what exists. Bring in the table that says what fired, one rule at a time.",
            choices: [
              { id: "a", text: "| join type=inner max=0 technique [| inputlookup notable_fires_12mon.csv | rename mitre_technique AS technique]", why: "21 rows. Joined on the tag, one firing rule lends its history to every rule that shares that tag, and CDZ-0612 now looks proven because a disabled rule fired in January. That's how a heatmap stays green.", apply: { op: "join", table: "notable_fires_12mon.csv", left: "technique", right: "mitre_technique", hideKey: true } },
              { id: "b", text: "| join type=inner rule_name [| inputlookup rule_test_log.csv | rename tested_rule AS rule_name]", why: "Three rows, and one says no alert. Useful for the next ticket, but this table records tests on purpose. The question is what fired on live data.", apply: { op: "join", table: "rule_test_log.csv", left: "rule_name", right: "tested_rule", hideKey: true } },
              { id: "c", text: "| join type=inner rule_name [| inputlookup notable_fires_12mon.csv | rename search_name AS rule_name]", right: true, why: "Six rules. An inner join keeps only rules with a match, so every rule that never fired dropped out. The rule itself is the key.", apply: { op: "join", table: "notable_fires_12mon.csv", left: "rule_name", right: "search_name", hideKey: true } },
            ],
          },
          {
            id: "group", ask: "Line 5: you have rules. The board asked about techniques. Group them.",
            choices: [
              { id: "a", text: "| stats count", why: "One number: 6. It says nothing about which techniques, and that's the kind of number the report already had.", apply: { op: "summarize", by: [], as: "count" } },
              { id: "b", text: "| stats count by rule_name", why: "Still six rows, one per rule, each counting 1. The question is one level up.", apply: { op: "summarize", by: ["rule_name"], as: "count" } },
              { id: "c", text: "| stats count by technique", right: true, why: "Three techniques. Four of the six firing rules sit on T1059.003, and the report counted those as depth. T1003.001, T1560.001 and T1567.002 carry tags, and no running rule on them has fired on live data.", apply: { op: "summarize", by: ["technique"], as: "count" } },
            ],
          },
        ],
        expect: 3,
        lesson: "14 rules, six techniques painted green, three that ever fired. Rule count measures effort, and the tag measures intent. Neither shows a rule works. Fired isn't proof either, since a rule can fire on nothing but noise, and never fired isn't failure: it means quiet or broken, and only a test can say which. That makes a never-fired rule a ticket.",
        primer: {
          title: "Measuring With SPL",
          fold: true,
          points: [
            "SPL is Splunk's Search Processing Language. Each `|` passes the rows to the next command.",
            "`| inputlookup file.csv` starts from a table instead of from events.",
            "`| where` keeps rows that pass a test. String comparison in `where` is exact.",
            "`| join type=inner key [subsearch]` keeps only the left rows that have a match on the key.",
            "`| stats count by field` gives one row per value of that field.",
          ],
          example: {
            label: "Worked example: which sites have a badge reader that works?",
            lines: [
              '`| inputlookup badge_readers.csv where type="door"`',
              "`| join type=inner reader_id [| inputlookup swipes_30d.csv]`",
              "`| stats count by site`",
              "A reader with no swipes in 30 days drops out at the join, so each site's count is its readers that really reported.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Walk the Intruder's Path",
        prompt: "Incident response has rebuilt the 19 days as six steps. Lior lays them over the coverage numbers from your search. Tagged rules is what the heatmap shows. Ever fired is what you just measured.",
        caption: "The intruder's path against coverage · rules enabled today",
        columns: ["Step", "ATT&CK technique", "Tagged rules", "Rules that ever fired"],
        rows: [
          ["1", "T1133 External Remote Services", "0", "0"],
          ["2", "T1003.001 LSASS Memory", "2", "0"],
          ["3", "T1021.002 SMB/Windows Admin Shares", "2", "1"],
          ["4", "T1039 Data from Network Shared Drive", "0", "0"],
          ["5", "T1560.001 Archive via Utility", "1", "0"],
          ["6", "T1567.002 Exfiltration to Cloud Storage", "1", "0"],
        ],
        questions: [
          { id: "alerts", q: "Step 1 has no tagged rule. How many alerts can that step raise today?", hint: "An alert needs a rule.", answer: ["0", "zero", "none"], why: "None. With no rule on the technique, the step happens and the SIEM stays silent, whatever the logs recorded." },
          { id: "proven", q: "How many of the six steps have a rule that has ever fired?", hint: "Read the last column.", answer: ["1", "one"], why: "One. The heatmap shows four steps covered. The measurement shows one." },
          { id: "first", q: "Which step number is the first where a rule that has fired stands in the way?", hint: "Walk down from step 1.", answer: ["3", "step 3"], why: "Step 3. The intruder gets through two steps before anything proven could speak, and by then has credentials. Even that one stayed quiet during the intrusion: the intruder used the share without the PsExec service the rule looks for." },
          { id: "tag", q: "CDZ-0720 Vault Share Mass Read exists, is enabled, and has no tag. Which step number does it belong to?", hint: "What does the rule watch?", answer: ["4", "step 4"], why: "Step 4, Data from Network Shared Drive. The rule is real, and the heatmap shows a gap because a heatmap only knows what the tags tell it." },
        ],
      },
    ],
    // ── Reading 3: the lifecycle ──
    "deteng-r3": [
      {
        kind: "sequence",
        title: "From Idea to Retirement",
        prompt: "CDZ-0307 never fired and failed nobody's test, because nobody tested it. Lior is rebuilding it from nothing and wants it done in the right order. Tap the stages from first to last.",
        items: [
          { id: "tune", text: "Tune: fix the logic, add narrow exclusions with an owner and a reason", note: "Every exclusion is a place an attacker could stand, so each one is written down." },
          { id: "threat", text: "Identify the threat: what must this rule catch, and why here?", note: "Sources: threat reports, past incidents, gaps on the heatmap." },
          { id: "review", text: "Review at least quarterly, and retire what no longer applies", note: "Attackers change, and so does the estate." },
          { id: "write", text: "Write the logic in Sigma and convert it for the SIEM", note: "Which log, which fields, which values, what volume or sequence." },
          { id: "shadow", text: "Deploy in alert-only mode for 2 to 4 weeks", note: "Low severity, no automated action. Every alert is classified." },
          { id: "history", text: "Test against historical logs and an attack simulation", note: "Does it catch the attack? How often would it fire in a normal week?" },
          { id: "promote", text: "Promote to production severity", note: "Only once precision meets the bar. Automated response can come now." },
        ],
        order: ["threat", "write", "history", "shadow", "tune", "promote", "review"],
        doneNote: "A rule is never finished. It moves from test to observation to production to review, and a rule that stops firing goes back through testing. When you measure precision in alert-only mode, count benign true positives with the false positives: they are real, authorised activity, and they still aren't attacks.",
        primer: {
          title: "Why Rules Earn Their Severity",
          fold: true,
          points: [
            "A rule is a sensor. A sensor is proven before anyone relies on it, and it needs servicing afterwards.",
            "**Alert-only mode** means the rule runs on live data at low severity, with no automatic action, while people classify what it catches.",
            "Each alert gets a label: **true positive** (an attack), **benign true positive** (real but authorised, like an admin script) or **false positive** (not what the rule was meant to catch).",
          ],
          example: {
            label: "Worked example: a smoke alarm for a new building",
            lines: [
              "Decide what the risk is, then choose the sensor.",
              "Try it with smoke in the workshop.",
              "Fit it with the siren off and log what it would have done.",
              "Move it away from the kitchen, then connect the siren.",
              "Service it every year, and remove it when the room changes use.",
            ],
          },
        },
      },
    ],
    // ── Reading 4: a Sigma rule field by field, the rewrite and the evasion round ──
    "deteng-r4": [
      {
        kind: "anatomy",
        title: "Anatomy of a Sigma Rule",
        prompt: "CDZ-0402 is one of the rules from your search, and this is its Sigma source. It watches for a scheduled task created to run something from a place users can write to. Read it field by field before anything gets rewritten.",
        source: "sigma/persistence/schtasks_user_folder.yml",
        fields: [
          { key: "title", value: "Scheduled Task Created From a User Folder", label: "Name", note: "What the analyst reads first on the alert. It names the behaviour." },
          { key: "id", value: "8c1e7a52-43f0-4b6e-9d27-1f6ab0c3e914", label: "Identity", note: "A UUID that follows the rule through renames, forks and updates." },
          { key: "status", value: "experimental", label: "Maturity", note: "experimental, then test, then stable: the rule's place in its own lifecycle." },
          { key: "logsource", value: "category: process_creation / product: windows", label: "Where to look", note: "The kind of log this rule is about. The converter turns it into the index and sourcetype the compiled query searches, and the query looks nowhere else." },
          { key: "detection.selection", value: "Image|endswith: '\\schtasks.exe'", label: "Named group", note: "A named set of field and value tests. Tests side by side in one group must all be true." },
          { key: "CommandLine|contains", value: "- '\\AppData\\'  - '\\Users\\Public\\'", label: "Two values, one field", note: "Written as a YAML list under one field. Any one of the values on the command line satisfies this test." },
          { key: "detection.filter", value: "ParentImage: 'C:\\Program Files\\PkgBot\\pkgbot.exe'", label: "Second group", note: "A second named group. On its own it does nothing until the next line uses it." },
          { key: "condition", value: "selection and not filter", label: "The decision", note: "How the named groups combine, using and, or and not. This is the line that says when the rule fires." },
          { key: "falsepositives", value: "Installers that schedule a one-off cleanup task", label: "What to rule out", note: "Plain words for the analyst who opens this alert months from now." },
          { key: "level", value: "medium", label: "Urgency", note: "How urgent the alert is. The scale runs from informational up to critical." },
          { key: "tags", value: "attack.persistence, attack.t1053.005", label: "ATT&CK", note: "Written by the author, and what a coverage heatmap reads." },
        ],
        summary: "Read a rule in the order the machine does: logsource picks the data, the detection groups test it, condition decides. A query that matches nothing returns zero rows, and zero rows raise no alert, so a rule can look calm for all sorts of reasons. Most engineers start from a community rule in SigmaHQ and tune these same fields for their own estate.",
      },
      {
        kind: "spotdiff",
        title: "Harder to Dodge",
        prompt: "A red-team consultant walked past Cadenza's certutil rule three different ways in one afternoon. Lior rewrote it. Compare the two versions and tap each line that closes a dodge. Some lines changed for other reasons, and those don't count.",
        goodTitle: "v1: the rule the red team walked past",
        suspectTitle: "v2: the rewrite",
        good: [
          "title: Certutil Url Cache Fetch",
          "status: stable",
          "logsource:",
          y(1, "category: process_creation"),
          y(1, "product: windows"),
          "detection:",
          y(1, "selection:"),
          y(2, "Image|endswith: '\\certutil.exe'"),
          y(2, "CommandLine|contains: '-urlcache'"),
          y(1, "filter:"),
          y(2, "Image|startswith: 'C:\\Build\\'"),
          y(1, "condition: selection and not filter"),
          "level: high",
          "tags: [attack.command-and-control, attack.t1105]",
        ],
        suspect: [
          "title: Certutil Downloads a Remote File",
          "status: test",
          "logsource:",
          y(1, "category: process_creation"),
          y(1, "product: windows"),
          "detection:",
          y(1, "selection:"),
          y(2, "OriginalFileName: 'CertUtil.exe'"),
          y(2, "CommandLine|windash|contains: '-urlcache'"),
          y(1, "filter:"),
          y(2, "ParentImage: 'C:\\Program Files\\PkgBot\\pkgbot.exe'"),
          y(1, "condition: selection and not filter"),
          "level: high",
          "tags: [attack.command-and-control, attack.t1105]",
        ],
        diffs: [
          { line: 7, why: "The dodge was a copy named cu.exe. Image is the path on disk, so it moved with the rename. OriginalFileName comes from the file's own version information, which a rename or copy leaves alone. Patching the binary can still change it, so this raises the cost rather than ending the game." },
          { line: 8, why: "The dodge was /urlcache. certutil takes a slash as well as a dash, and v1 only looked for the dash. windash makes Sigma search every dash form of the flag." },
          { line: 10, why: "The dodge was running from C:\\Build\\, where v1 excused everything. v2 excuses one parent program at one path that only administrators can write to, so the exception is as small as the business need." },
        ],
        decoys: [
          { line: 0, why: "A clearer title helps whoever reads the alert. The compiled query is exactly the same." },
          { line: 1, why: "New logic goes back to test until it has proved itself. That's the lifecycle working, and it changes nothing about what matches." },
        ],
        lesson: "A rewrite moves the rule off things the attacker can change for free. Match what the file is, not what it's called, match the flag in every form it can take, and keep exceptions small enough to name. Then back to test, because rewritten logic has proved nothing yet.",
        hud: "Tap the lines that make v2 harder to dodge",
        sameLine: "That line is the same in both versions.",
        winTitle: "Three dodges closed",
        howTo: [
          "Read v1 and v2 side by side, line by line.",
          "Tap a line in v2 that closes a way around the rule.",
          "A change that leaves the matching alone costs a life and tells you why.",
        ],
        primer: {
          title: "What Can the Attacker Change for Free?",
          fold: true,
          points: [
            "Sysmon is a free Windows service that logs process starts. `Image` is the full path of the file that ran, so it follows any rename.",
            "`OriginalFileName` is read from the PE (Portable Executable) header's version information, inside the file itself.",
            "Many Windows tools accept `/flag` as well as `-flag`. Sigma's `windash` modifier expands a dash flag to its other forms, and it goes before `contains`.",
            "An exclusion is a rule too. Ask who could stand inside it.",
          ],
          example: {
            label: "Worked example: mshta, another Windows tool",
            lines: [
              "`Image|endswith: '\\mshta.exe'` matches the tool where it lives.",
              "`copy mshta.exe m.exe` and that test no longer matches.",
              "`OriginalFileName: 'MSHTA.EXE'` still does, because the copy carries its header with it.",
            ],
          },
        },
      },
      {
        kind: "duel",
        title: "The Evasion Round",
        prompt: "Cadenza's red team plays the moves that beat the old rules. For each evasion, play the detection logic that still catches it. A card you've played is gone, and two of your cards don't survive anything.",
        attacker: "Cadenza's red team",
        moves: [
          { id: "m1", move: "The credential dumper is rebuilt", detail: "New hash, new file name. Your rule holds a list of known bad hashes for the old build.", counter: "behaviour", hint: "The file is new. What does it still have to do to get credentials?", why: "A rebuild changes the file and not the job. To read credentials the tool must open the memory of LSASS (Local Security Authority Subsystem Service), and Sysmon Event 10 records TargetImage and GrantedAccess when that happens, if your Sysmon config logs it." },
          { id: "m2", move: "The upload is cut to 30 MB an hour", detail: "Your rule fires above 500 MB in 5 minutes. The attacker read the rule and now lives just below it, around the clock.", counter: "baseline", hint: "Stop asking about one window. What's normal for this account?", why: "A fixed limit can be learned and stayed under. 30 MB an hour is 720 MB a day, and for an account that sends 20 MB a day that stands out against its own month." },
          { id: "m3", move: "Three quiet steps", detail: "A VPN sign-in from a home address. A read of a share. A zip file in Temp. All three happen at Cadenza every day.", counter: "correlate", hint: "No single event is odd. What about all of them together?", why: "Each event alone would only make noise. The same account doing all three inside 30 minutes is the detection. Only rules that join sources can see it." },
          { id: "m4", move: "certutil is swapped for bitsadmin, then curl", detail: "Same macro, same job, a different download tool each time. Your rule names one tool.", counter: "parent", hint: "The tool keeps changing. What stays the same around it?", why: "Listing tools is a race you lose. Word still has to start something, so matching the parent catches the next tool too. A macro that downloads from inside Word itself needs its own rule on the network event." },
          { id: "m5", move: "Sysmon is stopped on one laptop", detail: "Every rule that reads this host's Sysmon goes quiet at once. To the SOC, it looks like a calm night.", counter: "silence", hint: "What's left when the log itself stops?", why: "A rule can't fire on data that never arrives. Watching for a source that stops reporting turns the silence itself into the alert." },
        ],
        cards: [
          { id: "hash", name: "Add the new hash", effect: "One more entry on the list." },
          { id: "behaviour", name: "Behaviour: read of LSASS memory", effect: "Sysmon Event 10, whatever the file is called." },
          { id: "baseline", name: "Per-account baseline", effect: "Compares today's total with 30 days of that account." },
          { id: "parent", name: "Parent rule", effect: "Office starting any child tool." },
          { id: "level", name: "Raise the level to critical", effect: "A louder label on the same match." },
          { id: "correlate", name: "Correlation rule", effect: "Joins events from several sources for one account." },
          { id: "silence", name: "Silent-source check", effect: "Fires when a host that always logs stops sending." },
        ],
        lesson: "Move each rule away from what the attacker picks and toward what the technique needs: names and hashes are free to change, and a fixed limit can be read and stayed under. No rule is permanent, and one kind of logic won't cover everything. A program mixes kinds and checks the logs are still arriving.",
        primer: {
          title: "Who Controls What You Match?",
          fold: true,
          points: [
            "Every rule matches something. Ask who controls it.",
            "File names, hashes and tool choice belong to the attacker. They cost almost nothing to change.",
            "What the technique has to do on the system is harder to change. Logic built on that survives more evasions.",
            "A cheap signature still has value. It just shouldn't be the only thing standing there.",
          ],
          example: {
            label: "Worked example: a ransom note",
            lines: [
              "Rule: a file named READ_ME_NOW.txt appears.",
              "Evasion: the next build picks another name.",
              "What the technique still needs: one process rewriting hundreds of files in minutes.",
              "So the rule moves there, and the name stops mattering.",
            ],
          },
        },
      },
    ],
    // ── The boss: warm-ups, on other data ──
    "deteng-la1": [
      {
        kind: "worksheet",
        title: "How Far Did the Failures Spread?",
        prompt: "The rewritten rules are live and the logon rules are next. Three sources stand behind this week's failed logons. Cadenza locks an account after 5 bad tries. Work out each source's shape.",
        caption: "Failed logons by source · this week",
        columns: ["Source", "Failed logons", "Distinct accounts", "Window"],
        rows: [
          ["203.0.113.18", "300", "6", "12 min"],
          ["198.51.100.44", "118", "118", "30 min"],
          ["10.40.2.9", "9", "3", "60 min"],
        ],
        questions: [
          { id: "per", q: "How many tries per account did 203.0.113.18 make?", hint: "Failures divided by distinct accounts.", answer: ["50"], why: "300 / 6 = 50 tries on each account: a lot of guesses at a few targets." },
          { id: "lock", q: "Which source would have locked accounts out?", hint: "Compare tries per account with the limit of 5.", answer: ["203.0.113.18"], why: "50 tries per account crosses a limit of 5 at once, so the lockout policy stops this source early." },
          { id: "spray", q: "Which source spread its tries so no account came near a lockout, while testing the most accounts?", hint: "Tries per account, and how many accounts.", answer: ["198.51.100.44"], why: "One try each across 118 accounts: the spray shape, and the limit of 5 never comes into it. 10.40.2.9 is under the limit too, on only three accounts, and a later lab looks at it." },
        ],
        primer: {
          title: "The Shape of Failed Logons",
          fold: true,
          points: [
            "**Spread** = failed logons ÷ distinct accounts. It tells you the method better than either number alone.",
            "**Brute force** throws many guesses at a few accounts.",
            "**Password spraying** throws a few guesses at many accounts.",
            "Lockout policies commonly trip somewhere between 3 and 10 bad tries. A source that stays under the limit on every account never locks anything.",
          ],
          example: {
            label: "Worked example: a hotel corridor",
            lines: [
              "Each door locks itself after 5 bad swipes.",
              "120 bad swipes on 3 doors: `120 / 3 = 40` a door, so the locks trip.",
              "8 bad swipes on 2 doors: `8 / 2 = 4` a door, so they don't.",
            ],
          },
        },
      },
      {
        kind: "trace",
        title: "What Still Works?",
        prompt: "A separate case from last spring, and Lior's favourite lesson. A token for the music distribution API leaked from a build script. Follow the access log and see which move really ended it. Click the row that answers each step.",
        lead: "Token tok_dist_7f2 normally calls the API only from the build server, 10.40.5.20.",
        steps: [
          {
            id: "first",
            ask: "Find the first call that didn't come from the build server.",
            source: "Distribution API · access log · 09:58 to 10:06",
            columns: ["Time", "client_ip", "token", "request", "status"],
            rows: [
              ["09:58", "10.40.5.20", "tok_dist_7f2", "GET /catalog", "200"],
              ["10:02", "10.40.5.20", "tok_dist_7f2", "GET /catalog/pending", "200"],
              ["10:04", "203.0.113.70", "tok_dist_7f2", "GET /masters/pending", "200"],
              ["10:06", "10.40.5.20", "tok_dist_7f2", "POST /release/4471", "200"],
            ],
            answer: 2,
            why: "10:04, from an address nobody knows, with a valid token, on the unreleased masters.",
            learned: "203.0.113.70 is using tok_dist_7f2",
          },
          {
            id: "block",
            ask: "The firewall blocked 203.0.113.70 at 10:12. Find the first call after that from any address other than the build server.",
            source: "Distribution API · access log · 10:11 to 10:24",
            columns: ["Time", "client_ip", "token", "request", "status"],
            rows: [
              ["10:11", "203.0.113.70", "tok_dist_7f2", "GET /masters/pending", "200"],
              ["10:19", "198.51.100.30", "tok_dist_7f2", "GET /masters/pending", "200"],
              ["10:22", "10.40.5.20", "tok_dist_7f2", "GET /catalog", "200"],
              ["10:24", "198.51.100.30", "tok_dist_7f2", "GET /masters/4471/stems", "200"],
            ],
            answer: 1,
            why: "Seven minutes after the block, a new address and the same token, with a 200. The block took away an address.",
            learned: "After the block, the same token works from 198.51.100.30",
          },
          {
            id: "revoke",
            ask: "The token was revoked at 10:26. Find the first call the API refused.",
            source: "Distribution API · access log · 10:24 to 10:31",
            columns: ["Time", "client_ip", "token", "request", "status"],
            rows: [
              ["10:24", "198.51.100.30", "tok_dist_7f2", "GET /masters/4471/stems", "200"],
              ["10:25", "198.51.100.30", "tok_dist_7f2", "GET /masters/4472/stems", "200"],
              ["10:27", "198.51.100.30", "tok_dist_7f2", "GET /masters/4472/stems", "401"],
              ["10:28", "10.40.5.20", "tok_dist_7f2", "GET /catalog", "401"],
              ["10:31", "10.40.5.20", "tok_dist_8c1", "GET /catalog", "200"],
            ],
            answer: 2,
            why: "A 401 at 10:27. The moment the token died, every address holding it stopped, including the build server, which got a new token at 10:31. The thing that opened the door was the token, so that is what had to go.",
            learned: "Revoking the token ended the access from every address",
          },
        ],
        primer: {
          title: "What Is the Attacker Holding?",
          fold: true,
          points: [
            "Every intrusion runs on something that lets the attacker in: a token, a session, a key.",
            "An address only says where they are connecting from today, and addresses are cheap to replace.",
            "When you pick the first move, name the thing that still works from anywhere, then take that away.",
          ],
          example: {
            label: "Worked example: a copied key card",
            lines: [
              "A hotel key card is copied. Staff bar one man from the lobby.",
              "He comes in through the car park, and the card still opens the room.",
              "The desk cancels the card, and it stops working at every door at once.",
            ],
          },
        },
      },
    ],
    "deteng-flag1": [
      {
        kind: "anatomy",
        title: "Why Did This Logon Fail?",
        prompt: "That third source, 10.40.2.9, turned out to be a retired scan job still trying accounts IT deleted months ago. Windows records why every logon failed. Read one of its failures field by field.",
        source: "Windows Security log · Event 4625 · CDZ-DC01",
        fields: [
          { key: "EventID", value: "4625", label: "What happened", note: "An account failed to log on." },
          { key: "TargetUserName", value: "ca_scanold", label: "Account tried", note: "The name the caller supplied. It need not exist." },
          { key: "WorkstationName", value: "CDZ-SCAN02", label: "Claimed caller", note: "The name the client gave for itself." },
          { key: "IpAddress", value: "10.40.2.9", label: "Source" },
          { key: "LogonType", value: "3", label: "How", note: "Network logon." },
          { key: "AuthenticationPackageName", value: "NTLM" },
          { key: "Status", value: "0xC000006D", label: "General result", note: "The broad outcome: bad user name or authentication information." },
          { key: "SubStatus", value: "0xC0000064", label: "Exact reason", note: "0xC0000064: no such user name. 0xC000006A: the user exists and the password was wrong. 0xC0000072: the account is disabled." },
        ],
        summary: "Status gives the broad result, and SubStatus gives the reason, in codes defined by Windows. Here the account is gone, which fits a forgotten job. A SIEM may index the field under another name, such as Sub_Status, and the codes stay the same.",
      },
    ],
    "deteng-queryfill1": [
      {
        kind: "worksheet",
        title: "Counting Rows or Counting Things?",
        prompt: "Lior has a draft rule for one account opening many different shares, a classic sign of someone looking for what to take. Windows Event 5140 logs each share access on the file server. Work out by hand what each stats line would return.",
        caption: "index=wineventlog EventCode=5140 earliest=-1h",
        columns: ["_time", "host", "Account_Name", "Source_Address", "Share_Name"],
        rows: [
          ["14:02", "CDZ-FS01", "ca_backup", "10.40.9.5", "\\\\*\\Masters"],
          ["14:03", "CDZ-FS01", "ca_backup", "10.40.9.5", "\\\\*\\Masters"],
          ["14:05", "CDZ-FS01", "ca_backup", "10.40.9.5", "\\\\*\\Masters"],
          ["14:06", "CDZ-FS01", "ca_backup", "10.40.9.5", "\\\\*\\Masters"],
          ["14:07", "CDZ-FS01", "ca_backup", "10.40.9.5", "\\\\*\\Masters"],
          ["14:11", "CDZ-FS01", "t.ferrante", "10.40.6.31", "\\\\*\\Masters"],
          ["14:11", "CDZ-FS01", "t.ferrante", "10.40.6.31", "\\\\*\\Royalties"],
          ["14:12", "CDZ-FS02", "t.ferrante", "10.40.6.31", "\\\\*\\Contracts"],
          ["14:12", "CDZ-FS02", "t.ferrante", "10.40.6.31", "\\\\*\\Artwork"],
          ["14:13", "CDZ-FS02", "n.achebe", "10.40.7.12", "\\\\*\\Artwork"],
        ],
        questions: [
          { id: "count", q: "With stats count by Account_Name, which account comes out on top?", hint: "Count its rows.", answer: ["ca_backup"], why: "ca_backup has 5 rows and t.ferrante has 4. Rows measure activity, and a backup job is busy by design." },
          { id: "dc", q: "With stats dc(Share_Name) by Account_Name, what is the value for ca_backup?", hint: "How many different shares does it touch?", answer: ["1", "one"], why: "One. Five visits to the same share. The job's size stopped mattering once the question became how many different things it touched." },
          { id: "actor", q: "And for t.ferrante, with that same line?", hint: "Count the different share names on its rows.", answer: ["4", "four"], why: "Four different shares in two minutes. That is the shape the draft rule is after, and it only shows when the counter is per account." },
          { id: "host", q: "Now stats dc(Share_Name) by host. What is the value for CDZ-FS02?", hint: "Take every row logged by that server, whoever it was.", answer: ["2", "two"], why: "Two, and it no longer says anything about a person. host names the server that wrote the log, so t.ferrante's four shares split across two counters and mix with n.achebe's. The by field should name who is acting." },
        ],
        primer: {
          title: "count, dc and by",
          fold: true,
          points: [
            "`stats count` counts rows.",
            "`stats dc(field)` is the distinct count: how many **different** values that field holds. The long form is `distinct_count(field)`.",
            "`by field` decides whose counter each row lands on, and you get one result row per value of that field.",
            "`stats` runs on the fields left at that point, and `AS` names the result so a later `| where` can test it.",
          ],
          example: {
            label: "Worked example: a library's loans",
            lines: [
              "`| stats count AS loans, dc(title) AS titles by member`",
              "One member takes the same audiobook out 10 times: `loans=10, titles=1`.",
              "Another takes out 10 different books: `loans=10, titles=10`.",
              "`by branch` instead would mix every member of that branch together.",
            ],
          },
        },
      },
    ],
  },
};
