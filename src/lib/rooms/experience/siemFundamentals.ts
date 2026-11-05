import type { RoomExperience } from "./types";

// "Operation Control Tower" for the "siem-fundamentals" room.
// Script: docs/campaign/25-siem-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Northcross Airports (fictional). Lab data differs from the graded tasks: the
// rule-window sheet evaluates timelines, it never names a rule type for a
// spray (q1); the outcome queue has no SharePoint backup job (q2) and no
// missed VPN login (q3); the Wazuh drill is an SSH rule on a Linux agent, not
// la1's spray alert or its averages (flag1); and the KQL console queries
// SigninLogs and DeviceProcessEvents, never failed logons per account from
// SecurityEvent (qf1).
export const SIEM_FUNDAMENTALS: RoomExperience = {
  roomId: "siem-fundamentals",
  codename: "Operation Control Tower",
  theme: "siem",
  handler: { name: "Sofia Marín", role: "SIEM Engineer, Northcross Airports" },
  briefing: [
    "Northcross Airports. Three terminals, 40,000 devices, and 1.2 billion log events a day flowing into one SIEM.",
    "Sofia Marín runs it like the control tower runs the sky: every source on the radar, rules watching for collision courses, and analysts who can ask it anything.",
    "A SIEM is only as good as its rules, its tuning and the people querying it.",
    "Take a seat in the tower.",
  ],
  mission: "Match the SIEM's jobs to real examples, work out when a rule actually fires, sort alerts into true, benign and false positives, read a Wazuh alert field by field, and write your own KQL to answer questions no rule was built for.",
  estimate: "~45 min",
  look: { primary: "#22d3ee", secondary: "#fbbf24", warn: "#f43f5e" },
  scene: "radar",
  layout: "stage",
  story: {
    intro: { title: "1.2 Billion Events", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-intro-bbb8d7ec.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-intro-e6d7e1d7.jpg" },
    afterStation: {
      tower: { title: "Low and Slow", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch2-59104a35.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch2-3df6c1b7.jpg" },
      outcomes: { title: "Severity Is a Guess", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch3-a324daaa.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch3-6f177701.jpg" },
      query: { title: "Ask It Yourself", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-finale-fec33181.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-finale-062e3a72.jpg" },
    },
  },
  stations: [
    {
      id: "tower",
      label: "Air Traffic Control",
      topic: "What a SIEM does: aggregate, normalise, correlate, alert, retain, report",
      tagline: "Match each SIEM job to what it looks like on shift",
      building: "control",
      taskIds: ["siem-fund-r1"],
    },
    {
      id: "rules",
      label: "When Does It Fire?",
      topic: "Threshold, trend, anomaly and sequence rules · windows and evasion",
      tagline: "Run a rule against a timeline by hand",
      building: "lab",
      taskIds: ["siem-fund-r2", "siem-fund-q1"],
    },
    {
      id: "outcomes",
      label: "True, Benign or False",
      topic: "TP, benign TP, FP, FN · alert fatigue and tuning",
      tagline: "Clear a queue and label every outcome",
      building: "office",
      taskIds: ["siem-fund-r3", "siem-fund-q2", "siem-fund-q3"],
    },
    {
      id: "spray",
      label: "The Spray Alert",
      topic: "Reading a correlated alert's fields",
      tagline: "Read a Wazuh alert before the graded one",
      building: "archive",
      taskIds: ["siem-fund-la1", "siem-fund-flag1"],
    },
    {
      id: "query",
      label: "Ask Your Own Question",
      topic: "Hand-written searches in KQL and SPL",
      tagline: "Answer the questions no rule was built for",
      building: "ticket",
      taskIds: ["siem-fund-r4", "siem-fund-qf1"],
      boss: true,
    },
  ],
  personas: {
    "siem-fund-q1": { name: "Sofia Marín", role: "SIEM Engineer", line: "More than 20 failures across accounts in 60 seconds from one IP. What kind of rule is that?" },
    "siem-fund-q2": { name: "Sofia Marín", role: "SIEM Engineer", line: "200 alerts a day, 190 of them the backup service. What do we do with that rule?" },
    "siem-fund-q3": { name: "Sofia Marín", role: "SIEM Engineer", line: "Stolen credentials, a clean-looking VPN login, no alert. What do we call that?" },
  },
  briefings: {
    // ── Reading 1: what a SIEM does ──
    "siem-fund-r1": [
      {
        kind: "match",
        title: "The Tower's Jobs",
        prompt: "Six things that happened in Northcross's SIEM this morning. Match each one to the SIEM function doing the work.",
        pairs: [
          { id: "agg", left: "Firewall, Entra ID, baggage-system and EDR logs all land in one index", right: "Log aggregation", why: "One place to search instead of logging into each system." },
          { id: "norm", left: "srcip, SourceAddress and client_ip all become source.ip", right: "Normalisation", why: "A common schema, so one rule can read every source." },
          { id: "corr", left: "A VPN login from abroad plus a badge swipe at Terminal 2 for the same user, 10 minutes apart", right: "Correlation", why: "Two events that mean nothing alone and everything together." },
          { id: "alert", left: "A ticket opens in the queue with severity High and the matching events attached", right: "Alerting", why: "The rule's output, ready for an analyst." },
          { id: "ret", left: "Last March's logs are still searchable for the regulator", right: "Retention", why: "Keeping evidence for investigations and compliance." },
          { id: "dash", left: "The CISO's wall screen shows alerts per terminal per hour", right: "Dashboards and reporting", why: "The picture management steers by." },
        ],
      },
    ],
    // ── Reading 2: correlation rules ──
    "siem-fund-r2": [
      {
        kind: "tune",
        title: "The Fan-Out Rule",
        prompt: "Sofia is writing a correlation rule for lateral movement across the baggage network: one account signing on to many different hosts inside a short window. Choose the host count and the window, deploy, and see which accounts it catches.",
        eventColumn: "account and pattern",
        dials: [
          { id: "hosts", label: "Distinct hosts reached by one account", short: "hosts", min: 2, max: 30, step: 1, start: 2 },
          { id: "mins", label: "Inside this many minutes", short: "window", unit: "min", min: 1, max: 60, step: 1, start: 60, dir: "below" },
        ],
        events: [
          { id: "a1", label: "t.okafor: 9 hosts in 6 min, right after a VPN login", bad: true, values: { hosts: 9, mins: 6 } },
          { id: "a2", label: "svc-bagsync: 14 hosts in 11 min, from a source it never used", bad: true, values: { hosts: 14, mins: 11 } },
          { id: "a3", label: "r.lindqvist: 7 hosts in 14 min, one RDP hop after another", bad: true, values: { hosts: 7, mins: 14 } },
          { id: "a4", label: "d.huang: 22 hosts in 4 min", bad: true, values: { hosts: 22, mins: 4 } },
          { id: "a5", label: "m.sato: 5 hosts spread over 3 hours", bad: true, values: { hosts: 5, mins: 180 } },
          { id: "n1", label: "gate-config tool: 3 hosts in 2 min, every gate refresh", bad: false, values: { hosts: 3, mins: 2 } },
          { id: "n2", label: "helpdesk remote assist: 4 hosts in 25 min", bad: false, values: { hosts: 4, mins: 25 } },
          { id: "n3", label: "svc-patch: 140 hosts in 3 min, approved change window", bad: false, values: { hosts: 140, mins: 3 } },
          { id: "n4", label: "kiosk-bank operator: 5 hosts in 20 min", bad: false, values: { hosts: 5, mins: 20 } },
          { id: "n5", label: "shift lead: 5 hosts in 9 min across badge terminals", bad: false, values: { hosts: 5, mins: 9 } },
          { id: "n6", label: "backup agent: 8 hosts in 40 min", bad: false, values: { hosts: 8, mins: 40 } },
          { id: "n7", label: "e.cole: 2 hosts in 1 min", bad: false, values: { hosts: 2, mins: 1 } },
        ],
        goal: { catch: 4, maxFalse: 1 },
        lesson: "A fan-out rule is a threshold plus a window, and both dials matter: about 7 hosts inside 14 to 39 minutes catches the movers while the shift lead, the kiosk operator and the helpdesk stay quiet. Round numbers like 10 hosts in 10 minutes miss the slower hops. The patch service touches 140 hosts in 3 minutes and no dial can tell it from an attacker: it needs an exception for that account and change window, not a bigger number. The 3-hour mover slips under any short window, so it needs a second rule with a longer one. That is why a SIEM runs several rules, and why a quiet rule is not proof of a quiet network.",
      },
    ],
    // ── Reading 3: outcomes and fatigue ──
    "siem-fund-r3": [
      {
        kind: "queue",
        title: "Label the Outcome",
        prompt: "Four alerts from the overnight queue, each already investigated. Label each outcome; the label decides what happens to the rule.",
        console: "SIEM · closed-alert review · Northcross",
        actions: [
          { id: "tp", label: "True positive", tone: "escalate" },
          { id: "btp", label: "Benign true positive", tone: "close" },
          { id: "fp", label: "False positive: tune", tone: "contain" },
        ],
        alerts: [
          { id: "a", time: "01:12", severity: "High", rule: "Mass file rename on file share", entity: "NX-FS-01",
            fields: [{ k: "files renamed", v: "6,200" }, { k: "extension", v: ".lockx" }, { k: "finding", v: "ransom note in every folder" }],
            context: "The rule fired on real ransomware.", answer: "tp", why: "Real activity, really malicious. Escalate; the rule did its job." },
          { id: "b", time: "02:30", severity: "Medium", rule: "Admin tool on many hosts", entity: "svc_patch",
            fields: [{ k: "tool", v: "PsExec to 140 hosts" }, { k: "change", v: "CHG-9921, monthly patching" }, { k: "window", v: "02:00-04:00 approved" }],
            context: "PsExec really ran everywhere, under an approved change.", answer: "btp", why: "The rule caught exactly what it was written for; the approval makes it benign. Close with the ticket; don't weaken the rule." },
          { id: "c", time: "03:44", severity: "High", rule: "Possible credit card numbers in outbound email", entity: "ops-reports@",
            fields: [{ k: "matched", v: "7731 0042 1188 2290 in a flight-delay report" }, { k: "context", v: "it's a flight number plus seat codes, not a card" }],
            context: "The pattern matched something that isn't card data at all.", answer: "fp", why: "The rule misfired on look-alike text. Tune it narrowly: add a checksum (Luhn) test and require card context nearby, instead of switching the rule off." },
          { id: "d", time: "05:05", severity: "Low", rule: "Login from new country", entity: "j.berg",
            fields: [{ k: "country", v: "Brazil" }, { k: "MFA", v: "denied twice, then approved" }, { k: "user", v: "says they're at home in Oslo" }],
            context: "A login from a place the user isn't, after an MFA push storm.", answer: "tp", why: "Low severity, real compromise. Severity is the rule's guess; the investigation decides." },
        ],
      },
    ],
    // Drill before the graded spray alert: another Wazuh alert, field by field.
    "siem-fund-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Wazuh Alert",
        prompt: "Before the graded alert, read one Wazuh raised on a baggage-system Linux server.",
        source: "Wazuh · alerts.json · agent nx-bag-03",
        fields: [
          { key: "rule.id", value: "5712", label: "Which rule", note: "Wazuh's built-in SSH brute-force rule." },
          { key: "rule.description", value: "sshd: brute force trying to get access to the system. Authentication failed.", label: "What" },
          { key: "rule.level", value: "10", label: "Severity", note: "Wazuh levels run 0 to 15; 10 or more usually pages someone." },
          { key: "rule.firedtimes", value: "37", label: "How often", note: "How many times this rule has fired for this agent recently: a sense of scale." },
          { key: "rule.mitre.id", value: "T1110", label: "ATT&CK" },
          { key: "agent.name", value: "nx-bag-03", label: "Where" },
          { key: "data.srcip", value: "198.51.100.140", label: "From" },
          { key: "decoder.name", value: "sshd", label: "Parsed by", note: "The decoder that turned the raw line into fields." },
          { key: "full_log", value: "Nov  4 04:12:51 nx-bag-03 sshd[3321]: Failed password for root from 198.51.100.140 port 50211 ssh2", label: "The original line", note: "Always read the raw log the alert was built from." },
        ],
        summary: "Rule, level, count, place, source, decoder, raw line. Read the graded alert's fields the same way.",
      },
    ],
    // ── Reading 4: KQL and SPL ──
    "siem-fund-r4": [
      {
        kind: "intercept",
        title: "Queries at the Gate",
        prompt: "An alert names 203.0.113.58 in Northcross's sign-ins and no rule answers what comes next. Sofia pastes candidate queries into the Logs blade. Run the ones that answer the question under them; stop the ones that would return something misleading.",
        protect: "the hunt on 203.0.113.58",
        blockLabel: "Wrong query",
        passLabel: "Run it",
        seconds: 12,
        items: [
          { id: "q1", text: "SigninLogs | where IPAddress == \"203.0.113.58\" | summarize count() by UserPrincipalName", sub: "Which accounts did this IP touch?", bad: false, why: "summarize count() by UserPrincipalName gives one row per account, so the most-tried account stands out." },
          { id: "q2", text: "SigninLogs | where IPAddress == \"203.0.113.58\" | summarize count() by IPAddress", sub: "Which accounts did this IP touch?", bad: true, why: "You already filtered on the IP, so grouping by it returns one row and a total with no accounts. Group by the thing you do not know yet." },
          { id: "q3", text: "SigninLogs | where IPAddress == \"203.0.113.58\" | where ResultType != 0 | project UserPrincipalName", sub: "Which account did it actually get into?", bad: true, why: "ResultType 0 is success. != 0 lists the failures, the accounts it only tried, and hides the one that fell." },
          { id: "q4", text: "SigninLogs | where IPAddress == \"203.0.113.58\" | where ResultType == 0 | project TimeGenerated, UserPrincipalName, AppDisplayName", sub: "Which account did it actually get into?", bad: false, why: "Filtering on the outcome, not just the source, finds the sign-in that succeeded, and the app it went into." },
          { id: "q5", text: "SigninLogs | where IPAddress startswith \"203.0.113.5\"", sub: "Only this one address", bad: true, why: "startswith matches .5 and .50 through .59, ten addresses. Use == when you mean exactly one IP." },
          { id: "q6", text: "DeviceProcessEvents | where AccountName == \"k.mensah\" | project Timestamp, DeviceName, FileName, ProcessCommandLine", sub: "What did the compromised account run?", bad: false, why: "The pivot from identity to endpoint telemetry. DeviceProcessEvents stores the short account name." },
          { id: "q7", text: "DeviceProcessEvents | where AccountName == \"k.mensah@northcross.example\" | project Timestamp, FileName", sub: "What did the compromised account run?", bad: true, why: "AccountName is the short name, so the full sign-in name returns zero rows and looks like nothing ran. An empty result is not an all-clear." },
          { id: "q8", text: "SigninLogs | where TimeGenerated > ago(1h) | where IPAddress == \"203.0.113.58\"", sub: "Everything this IP did this week", bad: true, why: "Filtering on time first is right, but ago(1h) hides six days of activity. Match the window to the question: ago(7d)." },
          { id: "q9", text: "SigninLogs | where TimeGenerated > ago(7d) | where IPAddress == \"203.0.113.58\" | summarize arg_max(TimeGenerated, *) by UserPrincipalName", sub: "Latest sign-in per account this week", bad: false, why: "Time first, then the IP, then arg_max keeps the newest row per account: a compact answer from a big table." },
          { id: "q10", text: "SigninLogs | take 10 | where IPAddress == \"203.0.113.58\"", sub: "Every sign-in from this IP", bad: true, why: "take 10 keeps ten arbitrary rows before the filter runs, so most matches are never examined. Filter first, limit last." },
        ],
        lesson: "A hand-written query is a chain: narrow by time and source first, then pick the outcome, then summarize by what you do not yet know, then pivot to another table. Three traps repeat: grouping by the field you filtered on, matching the wrong form of a name so the result is empty, and limiting rows before filtering. An empty or tiny result is a reason to doubt the query before trusting the network.",
      },
    ],
  },
};
