import type { RoomExperience } from "./types";

// "Operation Signal to Noise" for the "detection-rules-tuning" room.
// Script: docs/campaign/37-detection-rules-tuning.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Glasshouse Media (fictional), not the graded tasks' corp.com. Lab data
// differs from the graded tasks: the logic sort has no sequence bucket and no
// failed-then-success example (q2); the Sigma anatomy never states why the
// format is vendor-neutral (q3) and is a Linux rule, not a spray; the tuning
// sheet is an out-of-hours RDP rule, never a password spray (q1), never names
// the exception-list term (flag1) and never measures recall (q4); and nothing
// judges the WSUS download (la1) or a spray sub-technique (q5).
export const DETECTION_RULES_TUNING: RoomExperience = {
  roomId: "detection-rules-tuning",
  codename: "Operation Signal to Noise",
  theme: "detection",
  handler: { name: "Ilse Brandt", role: "Detection Engineer, Glasshouse Media" },
  briefing: [
    "Glasshouse Media. A streaming service with 9 million subscribers, a content vault of unreleased shows, and a SOC of six people.",
    "Last quarter the SOC received 41,000 alerts. Two were real. One of those was closed as noise because the analyst had seen the same rule fire 300 times that week.",
    "Ilse Brandt writes and tunes the detections. She wants every rule to earn its place: clear logic, portable format, measured noise.",
    "Learn the four kinds of detection logic, read a Sigma rule, tune a noisy rule with numbers, then judge an alert and a spray.",
  ],
  mission: "Sort detections by their logic, read a Sigma rule section by section, tune an out-of-hours rule using its dispositions and precision, then judge a download alert and a spray.",
  estimate: "~35 min",
  look: { primary: "#a78bfa", secondary: "#34d399", warn: "#f87171" },
  scene: "noisefilter",
  layout: "stage",
  stations: [
    {
      id: "logic",
      label: "Logic Types",
      topic: "Threshold, sequence, correlation and anomaly detections",
      tagline: "Name the logic behind each rule",
      building: "control",
      taskIds: ["det-rules-r1", "det-rules-q2"],
    },
    {
      id: "sigma",
      label: "Read the Sigma",
      topic: "title, logsource, detection, condition, level, tags",
      tagline: "One rule, any SIEM",
      building: "lab",
      taskIds: ["det-rules-r2", "det-rules-q3"],
    },
    {
      id: "tune",
      label: "Tune the Noise",
      topic: "Why rules get noisy · exceptions, thresholds and context · priority and precision",
      tagline: "Cut noise without going blind",
      building: "office",
      taskIds: ["det-rules-r3", "det-rules-q1"],
    },
    {
      id: "judge",
      label: "Real or Benign?",
      topic: "Judging one alert · measuring a rule",
      tagline: "Look before you suppress",
      building: "vault",
      taskIds: ["det-rules-la1", "det-rules-q4"],
    },
    {
      id: "boss",
      label: "Earn Its Place",
      topic: "Spray versus guessing · the tuning vocabulary",
      tagline: "Prove the rule and the fix",
      building: "ticket",
      taskIds: ["det-rules-q5", "det-rules-flag1"],
      boss: true,
    },
  ],
  personas: {
    "det-rules-q2": { name: "Ilse Brandt", role: "Detection Engineer", line: "Five failures, then a success, same IP, 30 minutes. What kind of logic is that?" },
    "det-rules-q1": { name: "Ilse Brandt", role: "Detection Engineer", line: "The spray rule fires 200 times a day on Monday password-forgetters. Fix it." },
    "det-rules-la1": { name: "Ilse Brandt", role: "Detection Engineer", line: "PowerShell downloading at 02:14 on the WSUS server. Threat or job?" },
    "det-rules-q5": { name: "Ilse Brandt", role: "Detection Engineer", line: "One password, 60 accounts, once each. Name it precisely." },
  },
  briefings: {
    // ── Reading 1: logic types ──
    "det-rules-r1": [
      {
        kind: "sort",
        title: "What Kind of Logic?",
        prompt: "Six rules from Glasshouse's SIEM. Which kind of logic does each one use?",
        buckets: [
          { id: "threshold", label: "Threshold: count over a window" },
          { id: "correlation", label: "Correlation: two sources agree" },
          { id: "anomaly", label: "Anomaly: different from the baseline" },
        ],
        items: [
          { id: "dl", text: "More than 500 files downloaded from the content vault by one account in 10 minutes", bucket: "threshold", why: "One event type, counted against a fixed number in a window." },
          { id: "dns", text: "More than 200 NXDOMAIN answers for one host in 5 minutes", bucket: "threshold", why: "Counting a single kind of event: classic threshold." },
          { id: "vpnbadge", text: "A VPN login for a user whose building badge was used in the office in the same hour", bucket: "correlation", why: "Two different sources (VPN and badge system) disagree about where the person is." },
          { id: "edrfw", text: "An EDR alert on a host and a firewall deny from the same host to the same IP", bucket: "correlation", why: "Endpoint and network evidence joined on one host and one address." },
          { id: "egress", text: "An editor's upload volume three times their 30-day average", bucket: "anomaly", why: "No fixed number: the rule compares the user with their own baseline." },
          { id: "hours", text: "A build server talking to a country it has never contacted before", bucket: "anomaly", why: "'Never before' is a learned baseline, not a threshold you wrote." },
        ],
      },
    ],
    // ── Reading 2: Sigma ──
    "det-rules-r2": [
      {
        kind: "anatomy",
        title: "Anatomy of a Sigma Rule",
        prompt: "A rule Ilse wrote last week for Glasshouse's Linux transcoders, section by section.",
        source: "sigma/rules/linux/glasshouse_cron_from_tmp.yml",
        fields: [
          { key: "title", value: "Cron job runs a binary from /tmp", label: "Name" },
          { key: "status", value: "experimental", note: "New rules start experimental until their noise is measured." },
          { key: "logsource", value: "product: linux · service: cron", label: "Where to look", note: "Tells a converter which log type and table this rule reads." },
          { key: "detection.selection", value: "CommandLine|startswith: '/tmp/'", label: "What matches" },
          { key: "detection.filter", value: "User: 'transcode-svc' and CommandLine|contains: '/tmp/ffmpeg-cache/'", label: "What's excluded", note: "The known-good job that also runs from /tmp." },
          { key: "condition", value: "selection and not filter", label: "The logic" },
          { key: "falsepositives", value: "Vendor installers that unpack to /tmp", note: "Written down so the next analyst knows what noise to expect." },
          { key: "level", value: "high", label: "Severity" },
          { key: "tags", value: "attack.persistence · attack.t1053.003", label: "ATT&CK", note: "Feeds the coverage map." },
        ],
        summary: "Where to look, what matches, what's excluded, and how bad it is. Read any Sigma rule in that order.",
      },
    ],
    // ── Reading 3: tuning ──
    "det-rules-r3": [
      {
        kind: "worksheet",
        title: "The Noisy Rule",
        prompt: "Rule GH-022, 'Interactive RDP logon outside 07:00-19:00', fired 120 times last month. Here are the closed tickets, grouped.",
        caption: "GH-022 dispositions · October 2026",
        columns: ["account / pattern", "alerts", "disposition"],
        rows: [
          ["oncall-* accounts during a paged incident", "84", "benign true positive (on-call rota)"],
          ["svc-render on RENDER-07 (scheduled re-encode)", "30", "false positive (service, not a person)"],
          ["helpdesk.n.yusuf from a jump host", "5", "benign true positive (ticketed)"],
          ["m.adeyinka from 198.51.100.200, no ticket", "1", "true positive (stolen credentials)"],
        ],
        questions: [
          { id: "real", q: "How many of the 120 alerts were real attacks?", hint: "Only one disposition says true positive.", answer: ["1", "one"], why: "One in 120. Bury it under 119 others and it gets closed as noise." },
          { id: "precision", q: "What's the rule's precision, as a percentage? (real ÷ all alerts, round to one decimal)", hint: "1 ÷ 120 × 100", answer: ["0.8", "0.8%", "0.83", "0.83%"], why: "Under 1%. The fix isn't to delete the rule: it caught the one that mattered." },
          { id: "biggest", q: "Which single pattern would you address first?", hint: "Which row produces most of the noise?", answer: ["oncall", "on-call", "oncall-* accounts", "on-call rota"], why: "84 of 120 alerts from on-call staff during paged incidents. Join the rule to the paging system and they disappear, without hiding m.adeyinka." },
        ],
      },
    ],
  },
};
