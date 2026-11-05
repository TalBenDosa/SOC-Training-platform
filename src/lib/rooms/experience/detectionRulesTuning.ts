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
  story: {
    intro: { title: "41,000 Alerts, Two Real", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-intro-9f16f2d7.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-intro-b2f1cbfe.jpg" },
    afterStation: {
      sigma: { title: "Write It Once", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-ch2-e7913b49.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-ch2-91f72006.jpg" },
      tune: { title: "One in 120", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-ch3-e122cb61.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-ch3-2b078e33.jpg" },
      boss: { title: "Earn Its Place", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-finale-8e64aa29.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/detection-rules-tuning/signalnoise-finale-fc917eae.jpg" },
    },
  },
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
        kind: "rush",
        title: "Name That Logic",
        prompt: "Ilse reads out claims about Glasshouse's live rules and how they work. Call each one true or false before the clock runs out.",
        seconds: 60,
        target: 10,
        trueLabel: "True",
        falseLabel: "False",
        cards: [
          { id: "c1", text: "More than 500 files from the vault by one account in 10 minutes is threshold logic.", answer: true, why: "One kind of event counted against a fixed number in a window. Cross the number and it fires." },
          { id: "c2", text: "A VPN login plus a badge swipe in the office the same hour is threshold logic.", answer: false, why: "Two different sources joined and found to disagree is correlation. Neither log is a problem alone." },
          { id: "c3", text: "Upload volume at 3x a user's own 30-day average is anomaly logic.", answer: true, why: "No fixed number was written by anyone: the user is compared with their own learned baseline." },
          { id: "c4", text: "A hard limit of 50 GB a day per user is anomaly logic because it flags unusual volume.", answer: false, why: "It looks like anomaly detection but it is a fixed number, so it is a threshold. Anomaly means compared with a baseline." },
          { id: "c5", text: "Three MFA denials and then an approval for one user is sequence logic.", answer: true, why: "The order of events is the detection: denials first, then the approval that finished the story." },
          { id: "c6", text: "Sequence logic fires when the events happen in any order.", answer: false, why: "Order is the point. The same events backwards describe a different story." },
          { id: "c7", text: "An anomaly rule works on day one for a brand-new hire.", answer: false, why: "No history means no baseline. New accounts need a learning period or a fallback threshold." },
          { id: "c8", text: "A threshold rule counts one kind of event against a fixed number.", answer: true, why: "That is the whole mechanism, which is why it is easy to explain and easy to stay under." },
          { id: "c9", text: "An attacker who stays one below the limit every window is caught by a threshold rule.", answer: false, why: "Staying just under the number is the standard way around a threshold. Pair it with a longer window or an anomaly rule." },
          { id: "c10", text: "level: high in a rule means the match is confirmed malicious.", answer: false, why: "Severity is the rule author's judgement of how bad a match could be, not a verdict on this alert." },
          { id: "c11", text: "The severity set in a rule decides which queue the alert lands in.", answer: true, why: "It is routing information. That is why a mis-set level can bury a real attack in a low queue." },
          { id: "c12", text: "A correlation rule can fire on two events that are harmless on their own.", answer: true, why: "That is its purpose: the combination, across sources, is what is suspicious." },
          { id: "c13", text: "Anomaly rules need a number someone wrote by hand.", answer: false, why: "The baseline is learned from past behaviour. Only the sensitivity, like 3x, is chosen." },
          { id: "c14", text: "Joining badge logs to VPN logs needs two log sources.", answer: true, why: "Correlation across sources is exactly what a single-source threshold cannot do." },
        ],
        lesson: "Four words, four questions: how many events (threshold), in what order (sequence), across which sources (correlation), compared with whom (anomaly). Severity is a fifth thing entirely: it routes the alert and says nothing about whether this one is real.",
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
          { key: "tags", value: "attack.persistence · attack.t1053.003", label: "ATT&CK", note: "Feeds the coverage map. Sub-technique IDs matter: the number after the dot names a variant of the parent technique." },
        ],
        summary: "Where to look, what matches, what's excluded, and how bad it is. Read any Sigma rule in that order.",
      },
    ],
    // ── Reading 3: tuning ──
    "det-rules-r3": [
      {
        kind: "tune",
        title: "Vault Download Rule",
        prompt: "Rule GH-031 watches the content vault: it fires when one account pulls a lot of files in 10 minutes AND that is far above the account's own 30-day habit. Ilse has last month's closed tickets. Set the two thresholds so the rule catches the real thefts without burying them in noise.",
        eventColumn: "account and download",
        dials: [
          { id: "files", label: "Files pulled in 10 minutes", short: "files", min: 50, max: 1000, step: 50, start: 50 },
          { id: "ratio", label: "Times the account's own 30-day average", short: "x baseline", unit: "x", min: 1, max: 20, step: 1, start: 1 },
        ],
        events: [
          { id: "a1", label: "m.okonkwo: 600 files, 14x baseline, the week of a resignation", bad: true, values: { files: 600, ratio: 14 } },
          { id: "a2", label: "contractor key: 350 files, 9x baseline, from a new address", bad: true, values: { files: 350, ratio: 9 } },
          { id: "a3", label: "editor account: 150 files, 6x baseline, a slow siphon", bad: true, values: { files: 150, ratio: 6 } },
          { id: "a4", label: "sync client after a phish: 800 files, 11x baseline", bad: true, values: { files: 800, ratio: 11 } },
          { id: "a5", label: "stolen VPN login: 250 files, 12x baseline", bad: true, values: { files: 250, ratio: 12 } },
          { id: "n1", label: "render farm re-encode: 900 files, 1x baseline", bad: false, values: { files: 900, ratio: 1 } },
          { id: "n2", label: "colourist nightly archive: 500 files, 2x baseline", bad: false, values: { files: 500, ratio: 2 } },
          { id: "n3", label: "new hire onboarding sync: 300 files, 7x baseline", bad: false, values: { files: 300, ratio: 7 } },
          { id: "n4", label: "editor before a festival deadline: 400 files, 4x baseline", bad: false, values: { files: 400, ratio: 4 } },
          { id: "n5", label: "weekly full backup agent: 1000 files, 3x baseline", bad: false, values: { files: 1000, ratio: 3 } },
          { id: "n6", label: "QA test account: 120 files, 10x baseline", bad: false, values: { files: 120, ratio: 10 } },
          { id: "n7", label: "intern pulling a first-day pack: 200 files, 12x baseline", bad: false, values: { files: 200, ratio: 12 } },
        ],
        goal: { catch: 4, maxFalse: 1 },
        lesson: "Precision is real alerts divided by all alerts; recall is real attacks caught divided by all attacks. Raising files alone buries nothing but misses the 250-file theft; raising the multiple alone floods you with the QA account and the intern. Together, about 250 files at 8x to 9x the baseline catches 4 of 5 with no false alarm: precision 100%, recall 80%. The editor siphoning 150 files at 6x is the cost. The new-hire sync at 7x shows why you stop at 8, not at 5. Once a noisy pattern is confirmed benign, such as the render farm, add it to the rule's exception list rather than loosening the dials. Do not drop both dials to catch the last theft: that returns you to a rule that fires on everything, and the next real alert gets closed as noise.",
      },
    ],
  },
};
