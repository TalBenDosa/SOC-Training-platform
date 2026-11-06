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
  scene: "facilitytriage",
  layout: "facility",
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
          { id: "hours", time: "01:40", severity: "Low", rule: "Identity - Logon outside working hours", entity: "deck.crew.santander (14 users)",
            fields: [{ k: "logon time (UTC)", v: "yesterday 05:10-06:30" }, { k: "local time", v: "06:10-07:30 (CET, UTC+1)" }, { k: "rule window", v: "06:00-20:00 UTC" }],
            context: "Fourteen crew in the Spanish port logged on for yesterday's morning shift, and the rule ran in tonight's batch. The rule's window is in UTC; the crew work in local time.", answer: "fp", why: "The rule misfired: nothing out of hours happened. Close as false positive and ask for the window to be fixed." },
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
        kind: "defuse",
        title: "The 04:00 Slump",
        prompt: "Four in the morning, 212 alerts, and the first ferry sails at 05:40. Amara scores priority as severity times asset criticality times user risk, each 1 to 3. Each round is a moment in the queue: cut the one call that keeps the night safe before the clock runs out. Behind every call sit the five triage steps, in order: 1 understand what the rule triggered on, 2 examine the evidence in the raw log, 3 enrich with context (IP reputation, geolocation, host role, user department), 4 assess the potential impact, 5 make and document the decision.",
        device: "Night queue",
        seconds: 90,
        rounds: [
          { id: "pick", state: "Three alerts waiting. Crew Wi-Fi malware: severity 3, asset 1 (crew tablet), user risk 2. Ticket-gate admin change: severity 2, asset 3, user risk 2. Fuel-ordering mailbox rule: severity 1, asset 3, user risk 3.",
            wires: [{ id: "a", label: "Open the ticket-gate admin change first" }, { id: "b", label: "Open the crew Wi-Fi malware first, it has the highest severity" }, { id: "c", label: "Open the fuel-ordering mailbox rule first" }],
            cut: "a", hint: "Multiply the three numbers on each alert before you read any of them.",
            why: "2 x 3 x 2 = 12 beats 3 x 1 x 2 = 6 and 1 x 3 x 3 = 9. Highest severity is not highest priority: the asset and the user change the order." },
          { id: "age", state: "A gate-scanner offline alert has waited 38 minutes against a 60-minute target. A new alert, 2 minutes old, shows a ransom-note file written on the port operations share.",
            wires: [{ id: "a", label: "Finish the gate scanner ticket first, its target is closer" }, { id: "b", label: "Re-sort the whole queue oldest first so nothing breaches" }, { id: "c", label: "Switch to the ransom-note alert now" }],
            cut: "c", hint: "Age matters, but only after impact.",
            why: "An in-progress impact on a critical share outranks a ticket with minutes of slack. Hand the scanner to the next person rather than let both wait; sorting by age alone buries the new one." },
          { id: "batch", state: "Sixty alerts from one noisy rule. The first 59 closed as false positive, same account, same host, same hash. The 60th is from the ticketing server and the hash differs.",
            wires: [{ id: "a", label: "Open the 60th and check it alone" }, { id: "b", label: "Bulk-close all 60 as duplicates of the first 59" }, { id: "c", label: "Mute the rule until morning to cut the noise" }],
            cut: "a", hint: "What changed between the 59 and this one?",
            why: "A pattern earns a fast close only while every field matches. A new host and hash is a different alert wearing the same rule name; bulk-closing or muting hides exactly the one that differs." },
          { id: "hand", state: "05:15. One alert on the booking server is still undecided: the process is unfamiliar, the owner is not answering, and 25 minutes remain on your shift.",
            wires: [{ id: "a", label: "Close it as a false positive so the shift ends with a clean queue" }, { id: "b", label: "Escalate as indeterminate, with notes" }, { id: "c", label: "Leave it untouched for the day shift to find on their own" }],
            cut: "b", hint: "Nobody should have to repeat your work.",
            why: "An honest indeterminate escalation with your evidence lets Tier 2 start where you stopped. A false-positive close guesses, and leaving it untouched loses the 25 minutes you had." },
        ],
        lesson: "Triage is ordering under pressure: score first, break ties by impact rather than age, treat a changed field as a new alert even inside a familiar rule, and never turn doubt into a clean-looking close. The queue is empty when the decisions are right, not when the number is small.",
      },
    ],
    // ── Reading 3: benign patterns ──
    "alert-triage-r3": [
      {
        kind: "rush",
        title: "Close or Escalate?",
        prompt: "Amara fires alerts at you with the evidence attached. If the evidence really proves the activity is benign, close it. If it is only a claim, a guess or a near-match, escalate.",
        seconds: 60,
        target: 10,
        trueLabel: "Close it",
        falseLabel: "Escalate",
        cards: [
          { id: "c1", text: "Share read at 02:00. The backup job log shows that run, same server, same minute.", answer: true, why: "The alert matches the job's own record. Evidence, not a guess about what it probably was." },
          { id: "c2", text: "Share read at 02:00 looks like the backup, but the job log shows no run tonight.", answer: false, why: "Looks like is not proof. The record that should exist is missing, so the read is unexplained." },
          { id: "c3", text: "Mass file change at night. Change ticket names the script, the account and the window.", answer: true, why: "All three details line up with the paperwork, so it is a benign true positive." },
          { id: "c4", text: "Mass file change at night. An admin says it is their script. No ticket, no schedule.", answer: false, why: "A claim without a ticket or schedule is just someone changing many files at night. Ask for proof." },
          { id: "c5", text: "Ticket printer on NTLMv1. Its owner confirmed the device and a replacement date.", answer: true, why: "Known legacy, owned and scheduled for removal: benign, but keep it logged as a risk." },
          { id: "c6", text: "A host on NTLMv1 that nobody on the asset list owns.", answer: false, why: "No owner means no one can vouch for it. An unknown legacy device is a finding." },
          { id: "c7", text: "Booking app calls a new cloud API after an update. Release notes list that endpoint.", answer: true, why: "The vendor documents the new endpoint, so the new behaviour has a source." },
          { id: "c8", text: "Booking app calls a new cloud API. Vendor silent, release notes do not mention it.", answer: false, why: "New behaviour after an update needs the vendor's word, not an assumption." },
          { id: "c9", text: "Scanner hits 400 ports. It is the vulnerability team's address, and a window is open.", answer: true, why: "Known source, approved window: the scan is the work, so close with the window noted." },
          { id: "c10", text: "Scanner hits 400 ports from the vulnerability team's address. No scan was booked this week.", answer: false, why: "The address is right but the schedule is wrong. A trusted source outside its window is worth a call." },
          { id: "c11", text: "AV blocked a file on a training kiosk. Quarantine confirmed, no execution.", answer: true, why: "Blocked and contained on a low-value asset: closed with the quarantine record." },
          { id: "c12", text: "AV blocked a file here, but the same hash ran on a second host an hour earlier.", answer: false, why: "Blocked on one host does not mean contained. The earlier run is the part to investigate." },
          { id: "c13", text: "Payroll clerk logon at 03:10. Leave calendar shows her on holiday.", answer: false, why: "The activity contradicts a record you can check. Escalate: it may be her credentials." },
          { id: "c14", text: "Noisy rule, 59 closed false positives. This one matches their host, account and hash.", answer: true, why: "Every field matches a pattern already proven benign. A fast close is justified here." },
        ],
        lesson: "A benign pattern is only benign with proof you can point to: a ticket, a job log, an owner, a vendor note. When the proof is a claim, a near-match or a missing record, the call is escalate. Trusted sources outside their window, and contained alerts with a loose end, are the near-misses that cost you. When you do escalate a credential attack, name its shape with a Brute Force (T1110) sub-technique: T1110.001 password guessing (many passwords against one account), T1110.003 password spraying (one password against many accounts) and T1110.004 credential stuffing (leaked username and password pairs).",
      },
    ],
  },
};
