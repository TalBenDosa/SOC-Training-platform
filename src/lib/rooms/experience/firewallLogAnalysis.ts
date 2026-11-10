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
  scene: "facilityfirewallloganalysis",
  layout: "facility",
  story: {
    intro: { title: "Nine Days on the Line", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-intro-0eac2f31.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-intro-df4fea09.jpg" },
    afterStation: {
      logbook: { title: "Three Handwritings", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-ch2-8788398b.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-ch2-26e6a364.jpg" },
      patterns: { title: "Tick", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-ch3-1101694e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-ch3-095474b6.jpg" },
      verdict: { title: "Retire the Rule", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-finale-26ed7930.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/firewall-log-analysis/denyall-finale-841270ee.jpg" },
    },
  },
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
        kind: "intercept",
        title: "Read the Line, Raise the Hand",
        prompt: "Lines from three vendors scroll in from Calder's SIEM with the tags stripped. Viktor wants a hand raised only when the fields say something needs a human. Escalate those, dismiss the lines where the firewall did its job.",
        protect: "the Calder SOC queue",
        blockLabel: "Escalate",
        passLabel: "Dismiss",
        seconds: 11,
        items: [
          { id: "smbout", text: "logid=0000000013 type=traffic subtype=forward vd=root policyid=42 action=accept srcip=10.40.3.8 dstip=203.0.113.99 dstport=445", sub: "FortiGate, an OT workstation to a public address", bad: true, why: "FortiGate fields (logid, vd, policyid). An accept on SMB to the internet means the traffic left: no OT host should be sharing files with a public address." },
          { id: "sweep", text: "type=traffic subtype=forward policyid=0 action=deny srcip=10.40.5.31 dstip=10.40.8.17 dstport=22", sub: "FortiGate, the 200th different dstip from this host in two minutes", bad: true, why: "A deny is the control working, but one source hitting one port on hundreds of hosts is a scan in progress, and policyid=0 is the implicit deny that logs it. Count the pattern, not the line." },
          { id: "legacy", text: "TRAFFIC,end,rule=Legacy-Any-Out,from=OT-Mill,to=Untrust,app=ssl,session_end_reason=tcp-fin", sub: "PAN-OS, a mill printer subnet, 2 GB sent in one session", bad: true, why: "PAN-OS marks zones with from and to and names the App-ID. Allowed by a forgotten catch-all rule, a printer sending gigabytes out is the real story." },
          { id: "guest", text: "ProductFamily=Firewall Action=Accept rule_name=\"Temp vendor access\" inzone=Guest outzone=OT", sub: "Check Point, no change ticket for it", bad: true, why: "ProductFamily, rule_name and inzone/outzone are Check Point fields. Guest into OT should be denied, so an Accept through a temporary rule is the line that matters." },
          { id: "rdpin", text: "type=traffic subtype=forward policyid=3 action=accept srcip=203.0.113.88 dstip=10.40.3.8 dstport=3389", sub: "FortiGate, internet source to an OT workstation", bad: true, why: "Direction matters. An inbound accept on RDP from a public address is exposure, whichever vendor logs it." },
          { id: "hmi", text: "ProductFamily=Firewall Action=Accept rule_name=\"Mill HMI to SCADA\" inzone=Internal outzone=OT", sub: "Check Point, an approved rule with a change ticket", bad: false, why: "An Accept looks alarming only until you read the rule name: this is the approved HMI to SCADA path doing its job." },
          { id: "modbus", text: "TRAFFIC,drop,rule=interzone-default,from=Guest,to=OT-Mill,app=not-applicable,dport=502", sub: "PAN-OS, the first and only hit in six hours", bad: false, why: "interzone-default is the PAN-OS catch-all between zones. One dropped probe is the default deny working, with nothing to follow up unless it repeats." },
          { id: "telnet", text: "type=traffic subtype=forward policyid=0 action=deny srcip=203.0.113.200 dstip=10.40.2.5 dstport=23", sub: "FortiGate, an internet address, first hit today", bad: false, why: "Background internet noise dropped by the implicit deny. Telnet knocking from outside, once, is not an investigation." },
          { id: "historian", text: "TRAFFIC,end,rule=OT-to-Historian,from=OT-Mill,to=DC-Core,app=mssql-db,session_end_reason=tcp-fin", sub: "PAN-OS, the mill feeding production data", bad: false, why: "A named rule, the right zones, the right App-ID and a clean tcp-fin close: the everyday flow the rule was written for." },
          { id: "close", text: "type=traffic subtype=forward policyid=9 action=close srcip=10.40.3.8 dstip=10.60.1.10 dstport=1433", sub: "FortiGate, the same historian feed", bad: false, why: "On FortiGate action=close is an accepted session that ended normally, not a block. Different vendors use the same words differently." },
        ],
        lesson: "Learn each vendor's fingerprint fields, then ask the same three things of every line: did it pass or stop, in which direction, and is it one line or a pattern. Two more things to know when a line says the firewall stopped it. A drop sends the scanner nothing, while a reject answers with a TCP reset or an ICMP unreachable. And a denied attempt usually logs sentbyte=0 and rcvdbyte=0 with duration 0, because the policy matched the first packet and no session ever formed, so no data moved.",
      },
    ],
    // ── Reading 2: rhythm ──
    "fw-r2": [
      {
        kind: "defuse",
        title: "Overnight Watch",
        prompt: "The mill's firewall is logging all night and Viktor will not be back before the shift change. Read each state and cut the one call that is right before the clock runs out.",
        device: "Overnight firewall watch",
        seconds: 90,
        rounds: [
          {
            id: "sweep",
            state: "FortiGate, 01:02 to 01:04: srcip=10.40.5.31, dstport=22 every time, 254 different dstip values across 10.40.8.0/24, all action=deny. No change ticket.",
            wires: [
              { id: "vert", label: "Port scan: one host, many ports" },
              { id: "horiz", label: "Host sweep: one port, many hosts" },
              { id: "admin", label: "An admin checking SSH on the subnet" },
            ],
            cut: "horiz",
            hint: "Count what changes and what stays the same.",
            why: "One source port and destination port with the destination address changing every time is a sweep across hosts. A port scan keeps the host and varies the port. The deny means nothing got through, but the source host is still the one to look at.",
          },
          {
            id: "rhythm",
            state: "01:02:10, 01:11:10, 01:20:11, 01:29:10, 01:38:10: srcip=10.40.7.19 to 203.0.113.61:443, each sentbyte=612, rcvdbyte=1408.",
            wires: [
              { id: "person", label: "A person refreshing a dashboard" },
              { id: "backup", label: "A scheduled backup upload" },
              { id: "beacon", label: "A timer-driven check-in to the same address" },
            ],
            cut: "beacon",
            hint: "Subtract consecutive times and compare the byte columns.",
            why: "Nine minutes apart give or take a second, 612 out and 1,408 back every time: a machine on a timer sending the same message. People are irregular and backups send a lot more than 612 bytes.",
          },
          {
            id: "odd",
            state: "Same host, 01:24:40, between two check-ins: one session to 10.40.0.20 (the internal patch server), sentbyte=18,224, rcvdbyte=9,830,112, only once.",
            wires: [
              { id: "join", label: "Add it to the beacon: same host, same night" },
              { id: "update", label: "Set it aside: an internal one-off download" },
              { id: "exfil", label: "Escalate it as data leaving the mill tonight" },
            ],
            cut: "update",
            hint: "Which direction is the large number, and where does it go?",
            why: "The large number is received, from an internal server, once: the shape of an update download. Exfiltration would be large sent bytes to an outside address. It is noise beside the signal, and chasing it wastes the shift.",
          },
          {
            id: "contain",
            state: "The beacon to 203.0.113.61 is confirmed. The sender is an engineering PC, 10.40.7.19, on a mill network.",
            wires: [
              { id: "dst", label: "Block 203.0.113.61 at the perimeter and watch what else the PC does" },
              { id: "iso", label: "Isolate the PC but leave the perimeter rules untouched tonight" },
              { id: "both", label: "Block the address, isolate the PC, preserve the logs" },
            ],
            cut: "both",
            hint: "Each half alone leaves something open.",
            why: "Blocking only the destination leaves the implant on the PC free to try other addresses. Isolating only leaves the address open for any other infected host. Do both and keep the logs, because they are the evidence for scope.",
          },
        ],
        lesson: "Read a pattern before you judge a line: what repeats, what changes, which way the bytes go, and then contain both ends of the channel.",
      },
    ],
    // ── Reading 3: signature mechanic, first-match rulebase ──
    "fw-r3": [
      {
        kind: "simulate",
        title: "First Match Wins",
        prompt: "The mill's OT firewall checks each flow against its rules from the top, and the first rule that matches decides. Run four real flows through it and see which rule wins.",
        checks: [
          { name: "#1 Emergency-Block-10.40.7.19", question: "Source 10.40.7.19, any destination: deny and log in full (temporary, added by the SOC)" },
          { name: "#2 OT-Mill to Historian", question: "From OT-Mill to 10.60.1.10 on TCP 1433: allow" },
          { name: "#3 Legacy-Any-Out", question: "Any internal source to any destination on TCP 443: allow (owner: left 2023)" },
          { name: "#4 Deny-All", question: "Everything else: deny and log" },
        ],
        scenarios: [
          { id: "hmi", label: "Mill HMI 10.40.3.8 to the historian on 1433", detail: "The everyday flow that feeds production data.", results: ["fail", "pass", "fail", "fail"], why: ["Wrong source.", "Matches: OT-Mill to the historian on 1433.", "Never reached.", "Never reached."], verdict: "Rule #2. Exactly what it was written for." },
          { id: "eng", label: "Engineering PC 10.40.7.19 to 203.0.113.61:443", detail: "The nine-minute check-in.", results: ["pass", "fail", "fail", "fail"], why: ["The SOC's emergency rule catches it first, denies it and logs every attempt.", "Never reached.", "Never reached.", "Never reached."], verdict: "Rule #1. Placing the emergency deny rule at the top means nothing below can quietly allow this traffic." },
          { id: "printer", label: "Mill printer 10.40.9.2 to an internet address on 443", detail: "A printer that has no business on the internet.", results: ["fail", "fail", "pass", "fail"], why: ["Wrong source.", "Wrong destination and port.", "Legacy-Any-Out allows any internal host out on 443.", "Never reached."], verdict: "Rule #3, a forgotten catch-all with no owner, lets a printer reach the internet. That's the rule to retire." },
          { id: "smb", label: "Guest Wi-Fi 172.31.0.44 to the mill on 445", detail: "A visitor's laptop trying file shares in OT.", results: ["fail", "fail", "fail", "pass"], why: ["Wrong source.", "Wrong source and port.", "Port 445, not 443.", "Nothing above matched, so the default deny drops it."], verdict: "Rule #4. Default deny doing its job: worth watching its hit count for scanning." },
        ],
      },
    ],
  },
};
