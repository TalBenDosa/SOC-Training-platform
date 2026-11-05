import type { RoomExperience } from "./types";

// "Operation Deny All" for the "firewall-log-analysis" room.
// Script: docs/campaign/46-firewall-log-analysis.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Calder Steelworks (fictional), not the graded tasks' WKSTN hosts. Signature
// mechanic: a first-match rulebase simulator. Lab data differs from the graded
// tasks: the vendor sort never reads byte counters (q3) or reject versus drop
// (r1 checkpoint); the interval sheet never sweeps one host's ports (q1) or
// uses a 300-second beacon to 45.83.91.202 (q2); the rulebase never handles
// the blocked C2 session or its host (la1, flag1); and nothing judges the
// sales workstation's night traffic (ac1).
export const FIREWALL_LOG_ANALYSIS: RoomExperience = {
  roomId: "firewall-log-analysis",
  codename: "Operation Deny All",
  theme: "fwlogs",
  handler: { name: "Viktor Halloran", role: "Network Security Lead, Calder Steelworks" },
  briefing: [
    "Calder Steelworks. Two blast furnaces, a rolling mill, and a firewall estate of FortiGates, Palo Altos and Check Points bought by three different managers.",
    "Every packet that crosses a zone leaves a line in a log. Last month a contractor's laptop spent nine days calling home, and the lines were there all along.",
    "Viktor Halloran owns the firewalls. He wants analysts who read all three vendors, see a beacon in a column of timestamps, and know which rule actually let traffic through.",
    "Learn the fields, the threat patterns, the rulebase and the investigation steps, then work a blocked C2 attempt and a hard verdict.",
  ],
  mission: "Tell three vendors' logs apart by their fields, measure a beacon's rhythm from raw timestamps, run flows through a first-match rulebase to see which rule wins, then work the graded blocked-C2 log and a verdict.",
  estimate: "~40 min",
  look: { primary: "#f97316", secondary: "#38bdf8", warn: "#ef4444" },
  scene: "denyall",
  layout: "stage",
  stations: [
    {
      id: "logbook",
      label: "The Logbook",
      topic: "Core fields · stateful inspection · FortiGate, PAN-OS and Check Point formats",
      tagline: "Read three vendors' handwriting",
      building: "control",
      taskIds: ["fw-r1", "fw-q3"],
    },
    {
      id: "patterns",
      label: "Scans and Beacons",
      topic: "Port scans, the ticking clock of C2, inbound attacks, direction",
      tagline: "Hear the rhythm in the timestamps",
      building: "lab",
      taskIds: ["fw-r2", "fw-q1", "fw-q2"],
    },
    {
      id: "rulebase",
      label: "The Rulebase",
      topic: "Starting an investigation · pivots · rule hits, shadow rules · containment",
      tagline: "First match wins",
      building: "vault",
      taskIds: ["fw-r3"],
    },
    {
      id: "blocked",
      label: "Blocked Outbound",
      topic: "A blocked C2 attempt, field by field",
      tagline: "Work the graded log",
      building: "office",
      taskIds: ["fw-la1", "fw-flag1"],
    },
    {
      id: "verdict",
      label: "Beacon or Update",
      topic: "C2 or a legitimate updater",
      tagline: "Make the call",
      building: "ticket",
      taskIds: ["fw-ac1"],
      boss: true,
    },
  ],
  personas: {
    "fw-q3": { name: "Viktor Halloran", role: "Network Security Lead", line: "Deny, zero bytes both ways. What does that tell you?" },
    "fw-q1": { name: "Viktor Halloran", role: "Network Security Lead", line: "Twelve ports in 90 seconds from one internal host. Name it." },
    "fw-q2": { name: "Viktor Halloran", role: "Network Security Lead", line: "Every 300 seconds, 450 bytes out, for six hours. What is it?" },
    "fw-la1": { name: "Viktor Halloran", role: "Network Security Lead", line: "The firewall blocked it. Are we done?" },
    "fw-ac1": { name: "Viktor Halloran", role: "Network Security Lead", line: "A sales PC calling out at night. Beacon or updater?" },
  },
  briefings: {
    // ── Reading 1: three vendors ──
    "fw-r1": [
      {
        kind: "sort",
        title: "Whose Log Is This?",
        prompt: "Six lines pulled from Calder's SIEM with the vendor tag stripped off. Tell the FortiGate, PAN-OS and Check Point lines apart by their fields.",
        buckets: [
          { id: "forti", label: "FortiGate" },
          { id: "pan", label: "Palo Alto PAN-OS" },
          { id: "cp", label: "Check Point" },
        ],
        items: [
          { id: "f1", text: "logid=0000000013 type=traffic subtype=forward vd=root policyid=42 action=accept", bucket: "forti", why: "logid, type/subtype, vd (VDOM) and policyid are FortiGate's fingerprints." },
          { id: "p1", text: "TRAFFIC,end,rule=OT-to-Historian,from=OT-Mill,to=DC-Core,app=mssql-db,session_end_reason=tcp-fin", bucket: "pan", why: "Zones with from/to, App-ID in app, and session_end_reason: PAN-OS." },
          { id: "c1", text: "ProductFamily=Firewall Action=Accept rule_name=\"Mill HMI to SCADA\" inzone=Internal outzone=OT", bucket: "cp", why: "ProductFamily (the blade), rule_name, inzone/outzone: Check Point SmartConsole fields." },
          { id: "f2", text: "srccountry=Reserved dstcountry=Germany vd=OT policyid=7 action=deny", bucket: "forti", why: "srccountry/dstcountry with a VDOM and a policy number." },
          { id: "p2", text: "TRAFFIC,drop,rule=interzone-default,from=Guest,to=OT-Mill,app=not-applicable", bucket: "pan", why: "interzone-default is the PAN-OS catch-all rule between zones." },
          { id: "c2", text: "ProductFamily=IPS Action=Drop attack_name=\"Modbus Function Code Scan\"", bucket: "cp", why: "ProductFamily=IPS: the Check Point blade that raised it, not the firewall." },
        ],
      },
    ],
    // ── Reading 2: rhythm ──
    "fw-r2": [
      {
        kind: "worksheet",
        title: "Find the Rhythm",
        prompt: "Outbound sessions from the rolling mill's engineering PC overnight, straight from the firewall log. Measure the rhythm before anyone tells you what it is.",
        caption: "FortiGate · srcip=10.40.7.19 · dstport=443 · 01:00-01:30",
        columns: ["time", "dstip", "sentbyte", "rcvdbyte"],
        rows: [
          ["01:00:03", "198.51.100.212", "612", "1,408"],
          ["01:07:03", "198.51.100.212", "612", "1,408"],
          ["01:09:41", "10.40.0.20 (patch server)", "18,224", "9,830,112"],
          ["01:14:04", "198.51.100.212", "612", "1,408"],
          ["01:21:03", "198.51.100.212", "612", "1,408"],
          ["01:28:04", "198.51.100.212", "612", "1,408"],
        ],
        questions: [
          { id: "gap", q: "How many minutes apart are the sessions to 198.51.100.212?", hint: "Subtract consecutive times for that address only.", answer: ["7", "seven", "7 minutes"], why: "Every seven minutes, give or take a second: a machine on a timer, not a person." },
          { id: "same", q: "What is identical about every one of those sessions besides the timing?", hint: "Compare the byte columns.", answer: ["bytes", "the bytes", "byte counts", "size", "same bytes", "612 and 1408"], why: "612 out, 1,408 back, every time: the same check-in message and the same reply." },
          { id: "odd", q: "Which line breaks the pattern, and is it suspicious?", hint: "Different destination, different size.", answer: ["patch server", "10.40.0.20", "the patch server, no"], why: "The internal patch server: a big download once, the way updates look. Noise next to the signal." },
        ],
      },
    ],
    // ── Reading 3: signature mechanic, first-match rulebase ──
    "fw-r3": [
      {
        kind: "simulate",
        title: "First Match Wins",
        prompt: "The mill's OT firewall checks each flow against its rules from the top, and the first rule that matches decides. Run four real flows through it and see which rule wins.",
        checks: [
          { name: "#1 Emergency-Log-10.40.7.19", question: "Source 10.40.7.19, any destination: allow and log in full (temporary, added by the SOC)" },
          { name: "#2 OT-Mill to Historian", question: "From OT-Mill to 10.60.1.10 on TCP 1433: allow" },
          { name: "#3 Legacy-Any-Out", question: "Any internal source to any destination on TCP 443: allow (owner: left 2023)" },
          { name: "#4 Deny-All", question: "Everything else: deny and log" },
        ],
        scenarios: [
          { id: "hmi", label: "Mill HMI 10.40.3.8 to the historian on 1433", detail: "The everyday flow that feeds production data.", results: ["fail", "pass", "fail", "fail"], why: ["Wrong source.", "Matches: OT-Mill to the historian on 1433.", "Never reached.", "Never reached."], verdict: "Rule #2. Exactly what it was written for." },
          { id: "eng", label: "Engineering PC 10.40.7.19 to 198.51.100.212:443", detail: "The seven-minute check-in.", results: ["pass", "fail", "fail", "fail"], why: ["The SOC's emergency rule catches it first and logs every byte.", "Never reached.", "Never reached.", "Never reached."], verdict: "Rule #1. Placing the emergency log rule at the top means nothing below can quietly allow this traffic." },
          { id: "printer", label: "Mill printer 10.40.9.2 to an internet address on 443", detail: "A printer that has no business on the internet.", results: ["fail", "fail", "pass", "fail"], why: ["Wrong source.", "Wrong destination and port.", "Legacy-Any-Out allows any internal host out on 443.", "Never reached."], verdict: "Rule #3, a forgotten catch-all with no owner, lets a printer reach the internet. That's the rule to retire." },
          { id: "smb", label: "Guest Wi-Fi 172.31.0.44 to the mill on 445", detail: "A visitor's laptop trying file shares in OT.", results: ["fail", "fail", "fail", "pass"], why: ["Wrong source.", "Wrong source and port.", "Port 445, not 443.", "Nothing above matched, so the default deny drops it."], verdict: "Rule #4. Default deny doing its job: worth watching its hit count for scanning." },
        ],
      },
    ],
  },
};
