import type { RoomExperience } from "./types";

// "Operation Night Queue" for the "alert-triage" room.
// Script: docs/campaign/42-alert-triage.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Harbourline Ferries (fictional), not the graded tasks' CORP. Signature
// mechanic: an Incident Review queue with the four triage decisions. Lab data
// differs from the graded tasks: the queue never floods from one host (q1),
// never holds an RMM PowerShell (q2), a login anomaly (q3), a brute force
// (la1, flag1) or an unexplained server connection (q5); the priority sheet
// never weighs a rebuild-bound lab VM against an executive laptop (r1
// checkpoint); and nothing writes a closing note (q4).
export const ALERT_TRIAGE: RoomExperience = {
  roomId: "alert-triage",
  codename: "Operation Night Queue",
  theme: "nightqueue",
  handler: { name: "Amara Quinn", role: "SOC Shift Lead, Harbourline Ferries" },
  briefing: [
    "Harbourline Ferries. Nine ships, four ports, a booking system that sells 6,000 crossings a day, and a SOC that never sleeps.",
    "Tonight you're on the night shift with Amara Quinn. The queue has 212 alerts in it and the first ferry sails at 05:40.",
    "Most alerts are noise. A few are real. One mistake either way costs: a missed attack, or a wasted hour while the real one waits.",
    "Learn what triage is, the five steps from alert to decision, how to spot benign patterns, then work a brute-force alert and two hard calls.",
  ],
  mission: "Work the night queue with the four decisions analysts really make, rank alerts by severity, asset and user, match benign patterns to the proof that clears them, then work the graded brute-force alert.",
  estimate: "~40 min",
  look: { primary: "#f59e0b", secondary: "#38bdf8", warn: "#ef4444" },
  scene: "nightqueue",
  layout: "stage",
  stations: [
    {
      id: "queue",
      label: "The Queue",
      topic: "What triage is · TP, FP, benign TP, indeterminate · the priority matrix",
      tagline: "Four decisions, one queue",
      building: "control",
      taskIds: ["alert-triage-r1", "alert-triage-q1"],
    },
    {
      id: "steps",
      label: "Five Steps",
      topic: "Rule, raw log, enrichment, impact, decision",
      tagline: "Rank it before you open it",
      building: "lab",
      taskIds: ["alert-triage-r2", "alert-triage-q2"],
    },
    {
      id: "benign",
      label: "Benign or Not",
      topic: "Admin scripts, scanners, legacy systems, odd business apps · escalation · good tickets",
      tagline: "Know the proof that clears it",
      building: "office",
      taskIds: ["alert-triage-r3", "alert-triage-q3"],
    },
    {
      id: "brute",
      label: "347 Failures",
      topic: "A brute-force alert, field by field",
      tagline: "Work the graded alert",
      building: "vault",
      taskIds: ["alert-triage-la1", "alert-triage-flag1"],
    },
    {
      id: "handover",
      label: "Write It Up",
      topic: "Closing notes and knowing when to hand it up",
      tagline: "Leave the queue clean",
      building: "ticket",
      taskIds: ["alert-triage-q4", "alert-triage-q5"],
      boss: true,
    },
  ],
  personas: {
    "alert-triage-q1": { name: "Amara Quinn", role: "SOC Shift Lead", line: "A hundred alerts from one host over the weekend. Where do you start?" },
    "alert-triage-q2": { name: "Amara Quinn", role: "SOC Shift Lead", line: "Encoded PowerShell from the IT team's RMM agent, ticket open. Your call." },
    "alert-triage-la1": { name: "Amara Quinn", role: "SOC Shift Lead", line: "347 failures against administrator in five minutes. Read it." },
    "alert-triage-q5": { name: "Amara Quinn", role: "SOC Shift Lead", line: "Twenty minutes in and you still can't tell. What now?" },
  },
  briefings: {
    // ── Reading 1: signature mechanic, the Incident Review queue ──
    "alert-triage-r1": [
      {
        kind: "queue",
        title: "The Night Queue",
        prompt: "Four alerts from tonight's Incident Review. For each, read the fields and the context, then make the decision an analyst would record.",
        console: "Splunk ES · Incident Review · Urgency: all · Status: New",
        actions: [
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "tp", label: "Escalate: true positive", tone: "escalate" },
          { id: "ind", label: "Escalate: indeterminate", tone: "contain" },
        ],
        alerts: [
          { id: "usb", time: "01:12", severity: "Medium", rule: "Endpoint - USB mass storage connected", entity: "MV-AURORA-BRIDGE-02",
            fields: [{ k: "user", v: "second.officer" }, { k: "device", v: "Kingston 32GB" }, { k: "files read", v: "ENC_charts_2026-11.zip" }, { k: "ticket", v: "MT-2231 chart update, approved" }],
            context: "The vendor's monthly electronic chart update, loaded from USB on the bridge, as the maintenance ticket says.", answer: "btp", why: "The rule fired correctly: a USB really was connected. The activity is authorised and ticketed. Record MT-2231 and close." },
          { id: "hours", time: "01:40", severity: "Low", rule: "Identity - Logon outside working hours", entity: "deck.crew.portsmouth (14 users)",
            fields: [{ k: "logon time (UTC)", v: "05:10-06:30" }, { k: "local time", v: "06:10-07:30 (UTC+1)" }, { k: "rule window", v: "06:00-20:00 UTC" }],
            context: "Fourteen crew logged on for the morning shift. The rule's window is in UTC; the crew work in local time.", answer: "fp", why: "The rule misfired: nothing out of hours happened. Close as false positive and ask for the window to be fixed." },
          { id: "svc", time: "02:05", severity: "High", rule: "Endpoint - New service installed", entity: "HL-BOOKING-APP-01",
            fields: [{ k: "service", v: "svc_upd" }, { k: "binary", v: "C:\\Users\\Public\\svc_upd.exe (unsigned)" }, { k: "installed by", v: "booking.svc" }, { k: "change ticket", v: "none" }],
            context: "A new SYSTEM service on the booking server, from a public folder, installed by an application account, with no change on record.", answer: "tp", why: "Unsigned, user-writable path, no change, on the system that sells every ticket. Escalate as a true positive now." },
          { id: "cctv", time: "02:30", severity: "Medium", rule: "Network - Large outbound transfer", entity: "HL-CCTV-NVR-03",
            fields: [{ k: "destination", v: "203.0.113.140:443" }, { k: "volume", v: "3.4 GB" }, { k: "vendor contacted", v: "no answer until 08:00" }],
            context: "The terminal's CCTV recorder sent 3.4 GB out. It might be the vendor's cloud backup; nobody can confirm tonight.", answer: "ind", why: "Not enough evidence either way. Escalate as indeterminate with what you checked, so Tier 2 picks it up with the vendor in the morning." },
        ],
      },
    ],
    // ── Reading 2: ranking ──
    "alert-triage-r2": [
      {
        kind: "worksheet",
        title: "Rank the Queue",
        prompt: "Amara scores priority as severity × asset criticality × user risk (each 1 to 3). Work out where each alert sits before you open any of them.",
        caption: "Harbourline priority matrix · tonight's top four",
        columns: ["alert", "severity", "asset criticality", "user risk", "priority"],
        rows: [
          ["Phishing link clicked", "2", "3 (port operations PC)", "2", "?"],
          ["Malware blocked", "3", "1 (training kiosk)", "1", "?"],
          ["Admin role granted", "2", "3 (booking database)", "3", "?"],
          ["Port scan from guest Wi-Fi", "1", "2 (onboard guest network)", "1", "?"],
        ],
        questions: [
          { id: "top", q: "Which alert do you open first?", hint: "Multiply the three numbers on each row.", answer: ["admin role granted", "admin role"], why: "2 × 3 × 3 = 18, the highest. A medium-severity alert on the system that sells every ticket outranks a high one on a kiosk." },
          { id: "malware", q: "What priority score does 'Malware blocked' get?", hint: "3 × 1 × 1", answer: ["3"], why: "High severity, but blocked, on a kiosk nobody signs in to with real credentials." },
          { id: "last", q: "Which alert can wait the longest?", hint: "Lowest product.", answer: ["port scan from guest wi-fi", "port scan", "guest wi-fi"], why: "1 × 2 × 1 = 2. It still gets looked at, just last." },
        ],
      },
    ],
    // ── Reading 3: benign patterns ──
    "alert-triage-r3": [
      {
        kind: "match",
        title: "The Proof That Clears It",
        prompt: "Each benign pattern on the left is only benign if you can prove it. Pair it with the evidence that proves it.",
        pairs: [
          { id: "script", left: "An IT admin's nightly script trips a 'mass file change' rule", right: "A change ticket or job schedule that names the script, the account and the time", why: "Without the paperwork it's just someone changing lots of files at night." },
          { id: "legacy", left: "An old ticket printer at the terminal still authenticates with NTLMv1", right: "The asset owner confirming the device and its replacement date", why: "Known legacy, owned and scheduled for removal: benign, but logged as a risk." },
          { id: "backup", left: "The backup server reads every file share at 02:00", right: "The backup job's own log showing the same run at the same time", why: "Match the alert to the job's record, not to a guess about what it probably was." },
          { id: "vendor", left: "The booking app calls an unfamiliar cloud API after an update", right: "The vendor's release notes or support confirming the new endpoint", why: "New behaviour after an update needs the vendor's word, not an assumption." },
        ],
      },
    ],
  },
};
