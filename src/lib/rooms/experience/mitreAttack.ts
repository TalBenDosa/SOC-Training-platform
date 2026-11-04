import type { RoomExperience } from "./types";

// "Operation Common Tongue" for the "mitre-attack" room.
// Script: docs/campaign/33-mitre-attack.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Marlow Aerospace (fictional), not the graded tasks' Fintech-Global. Lab data
// differs from the graded tasks: the ID sort never defines tactic versus
// technique in words (q1); the tactic sort never uses ransomware encryption
// (q2), phishing, lateral movement, collection, persistence, initial access
// or exfiltration (m1, q4); the coverage sheet never names the tool (q3) or
// APT29; and the anatomy is an LSASS-access alert, never a password spray (la1).
export const MITRE_ATTACK: RoomExperience = {
  roomId: "mitre-attack",
  codename: "Operation Common Tongue",
  theme: "attack",
  handler: { name: "Jonah Whitfield", role: "Detection Engineering Lead, Marlow Aerospace" },
  briefing: [
    "Marlow Aerospace. Wing assemblies for three airliners, and design files that two nation-state groups have tried to steal this year.",
    "Last quarter four teams wrote four incident reports about the same intrusion, and none of them used the same words.",
    "Jonah Whitfield leads detection engineering. He wants one language: ATT&CK tactic and technique IDs on every alert, rule and report.",
    "Learn to read the IDs, place an action under its goal, find blind spots against a known group, and tag an alert the way the world does.",
  ],
  mission: "Sort ATT&CK IDs into tactics, techniques and sub-techniques, place attacker actions under the right goal, find the blind spots in Marlow's coverage against a known group, and read how an alert carries its ATT&CK mapping.",
  estimate: "~35 min",
  look: { primary: "#f87171", secondary: "#94a3b8", warn: "#fbbf24" },
  scene: "matrixwall",
  layout: "stage",
  stations: [
    {
      id: "ids",
      label: "Read the IDs",
      topic: "TA, T and the dot · Enterprise, Mobile and ICS",
      tagline: "Decode the notation",
      building: "control",
      taskIds: ["mitre-r1"],
    },
    {
      id: "tactics",
      label: "The 15 Goals",
      topic: "Tactics are the why, techniques the how · v19 Stealth and Defense Impairment",
      tagline: "Put each action under its goal",
      building: "lab",
      taskIds: ["mitre-r2", "mitre-q1", "mitre-q2"],
    },
    {
      id: "coverage",
      label: "Blind Spots",
      topic: "Coverage maps · threat-informed defence · detection engineering",
      tagline: "Find what nobody is watching",
      building: "vault",
      taskIds: ["mitre-r3", "mitre-q3"],
    },
    {
      id: "alert",
      label: "Map the Alert",
      topic: "From a log to a technique, a tactic and a mitigation",
      tagline: "Read an alert in ATT&CK",
      building: "office",
      taskIds: ["mitre-la1"],
    },
    {
      id: "report",
      label: "Tag the Report",
      topic: "Tactics across a whole intrusion",
      tagline: "Write it in the common tongue",
      building: "ticket",
      taskIds: ["mitre-m1", "mitre-q4"],
      boss: true,
    },
  ],
  personas: {
    "mitre-q1": { name: "Jonah Whitfield", role: "Detection Engineering Lead", line: "New hire question, but get it exact: tactic or technique?" },
    "mitre-q2": { name: "Jonah Whitfield", role: "Detection Engineering Lead", line: "Every file server encrypted. Which goal is that?" },
    "mitre-q3": { name: "Jonah Whitfield", role: "Detection Engineering Lead", line: "APT29 is coming for our sector. Show me our blind spots against them." },
    "mitre-la1": { name: "Jonah Whitfield", role: "Detection Engineering Lead", line: "Eight accounts, one address, three minutes. Name it in ATT&CK." },
    "mitre-q4": { name: "Jonah Whitfield", role: "Detection Engineering Lead", line: "Three steps of one breach. Tag them for the report." },
  },
  briefings: {
    // ── Reading 1: the notation ──
    "mitre-r1": [
      {
        kind: "sort",
        title: "Decode the Notation",
        prompt: "IDs from this week's Marlow alerts and reports. Is each one a tactic, a technique, or a sub-technique?",
        buckets: [
          { id: "tactic", label: "Tactic (TA....)" },
          { id: "tech", label: "Technique (T....)" },
          { id: "sub", label: "Sub-technique (T....xxx)" },
        ],
        items: [
          { id: "ta7", text: "TA0007", bucket: "tactic", why: "TA plus four digits: a tactic, here Discovery." },
          { id: "t1021", text: "T1021", bucket: "tech", why: "T plus four digits, no dot: the technique Remote Services." },
          { id: "t1021001", text: "T1021.001", bucket: "sub", why: "The dot adds the variant: Remote Desktop Protocol under Remote Services." },
          { id: "ta112", text: "TA0112", bucket: "tactic", why: "Defense Impairment, the tactic v19 added in April 2026." },
          { id: "t1059001", text: "T1059.001", bucket: "sub", why: "PowerShell, a sub-technique of Command and Scripting Interpreter." },
          { id: "t1003", text: "T1003", bucket: "tech", why: "OS Credential Dumping, with LSASS Memory as .001 underneath." },
        ],
      },
    ],
    // ── Reading 2: the tactics ──
    "mitre-r2": [
      {
        kind: "tricks",
        title: "Same Trick, Different Burglar",
        prompt: "Eight burglar tricks, each matching an action from Marlow's last red-team exercise. Flip each card and stamp it with the ATT&CK goal it serves.",
        attacks: [
          { id: "disc", name: "Discovery" },
          { id: "stealth", name: "Stealth" },
          { id: "impair", name: "Defense Impairment" },
          { id: "c2", name: "Command and Control" },
        ],
        cards: [
          { id: "nltest", analogy: "Walks the corridors reading every door sign and fire plan.", attack: "disc", real: "nltest /domain_trusts: listing which domains trust which." },
          { id: "netgroup", analogy: "Reads the staff board to see who holds the master keys.", attack: "disc", real: "net group \"Domain Admins\" /domain: finding who holds the keys." },
          { id: "rename", analogy: "Wears the cleaning crew's uniform so nobody looks twice.", attack: "stealth", real: "A dumping tool renamed to svchost.exe in C:\\Windows\\Temp." },
          { id: "timestomp", analogy: "Sets the arrival stamp in the visitor book to last year.", attack: "stealth", real: "A dropped DLL's timestamps set to match kernel32.dll." },
          { id: "stopedr", analogy: "Cuts the wire to the alarm panel.", attack: "impair", real: "sc stop on the EDR sensor service." },
          { id: "auditpol", analogy: "Switches the CCTV recorder off.", attack: "impair", real: "auditpol turning logon auditing off." },
          { id: "https", analogy: "Phones the getaway driver every 90 seconds on an ordinary line.", attack: "c2", real: "An implant checking in over HTTPS to a cloud CDN." },
          { id: "dns", analogy: "Passes notes hidden in the daily newspaper.", attack: "c2", real: "Commands carried in TXT answers for random subdomains." },
        ],
      },
    ],
    // ── Reading 3: coverage ──
    "mitre-r3": [
      {
        kind: "worksheet",
        title: "Find the Blind Spots",
        prompt: "Threat intel says SILVER HERON, a fictional group for this exercise, is targeting aerospace suppliers. Jonah lined up its known techniques against Marlow's detection rules.",
        caption: "Coverage layer · SILVER HERON techniques vs Marlow SIEM rules",
        columns: ["tactic", "technique", "Marlow rule", "covered?"],
        rows: [
          ["Initial Access", "T1190 Exploit Public-Facing Application", "WAF-EXP-01", "yes"],
          ["Execution", "T1059.001 PowerShell", "EDR-PS-ENC", "yes"],
          ["Credential Access", "T1003.001 LSASS Memory", "EDR-LSASS-03", "yes"],
          ["Discovery", "T1482 Domain Trust Discovery", "none", "no"],
          ["Lateral Movement", "T1021.002 SMB/Windows Admin Shares", "none", "no"],
          ["Exfiltration", "T1567.002 Exfiltration to Cloud Storage", "DLP-CLOUD-02", "yes"],
        ],
        questions: [
          { id: "count", q: "How many of SILVER HERON's techniques have no rule?", hint: "Count the 'no' rows.", answer: ["2", "two"], why: "Two blind spots: the quiet middle of the intrusion, after the break-in and before the theft." },
          { id: "first", q: "Which uncovered technique would you build a rule for first? (ID)", hint: "Which one lets them reach more machines?", answer: ["t1021.002", "t1021"], why: "SMB admin shares is how one foothold becomes fifty. Domain trust discovery is worth a rule too, but it's quieter and rarer." },
        ],
      },
    ],
    // Drill before the graded alert: an alert that carries its ATT&CK mapping.
    "mitre-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Mapped Alert",
        prompt: "Before the graded sign-in alert: a Defender for Endpoint alert from Marlow's design floor, and where its ATT&CK mapping lives.",
        source: "Microsoft Defender XDR · AlertInfo + AlertEvidence · DSN-WS-118",
        fields: [
          { key: "Title", value: "Suspicious access to LSASS service", label: "What fired" },
          { key: "Category", value: "CredentialAccess", label: "Tactic", note: "Defender writes the tactic name without spaces." },
          { key: "AttackTechniques", value: "[\"OS Credential Dumping (T1003)\",\"LSASS Memory (T1003.001)\"]", label: "Technique", note: "Both levels: the technique and its sub-technique." },
          { key: "Severity", value: "High" },
          { key: "DeviceName", value: "dsn-ws-118.marlow.example", label: "Where" },
          { key: "FileName", value: "rundll32.exe", label: "Actor" },
          { key: "ProcessCommandLine", value: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Windows\\Temp\\d.bin full", label: "Evidence", note: "The behaviour that earned the mapping." },
          { key: "ServiceSource", value: "Microsoft Defender for Endpoint" },
        ],
        summary: "Tactic, technique, sub-technique and the evidence behind them. In the graded alert the mapping sits in mitre_technique and mitre_tactic: check that the evidence actually fits it.",
      },
    ],
  },
};
