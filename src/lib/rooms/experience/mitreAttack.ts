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
        kind: "codebreak",
        title: "Crack the ID",
        prompt: "Jonah reads four clues from Marlow's red-team report and wants the exact ATT&CK ID for each. Letter feedback tells you which characters are in the right place. Write a dot-free sub-technique ID as one string, for example T1234567. Jonah's pattern: TA plus four digits is a tactic, T plus four digits is a technique, and a dot adds a variant. For Remote Services T1021, for example, .002 is SMB/Windows Admin Shares, .004 is SSH and .006 is Windows Remote Management.",
        tries: 6,
        rounds: [
          { id: "r1", clue: "Marlow's red team lands on one design workstation, then reaches a second host. The tactic for that goal, as a TA ID.", answer: "TA0008", why: "TA plus four digits is a tactic. Reaching other machines from the first one is Lateral Movement, TA0008. The goal comes first, the method (a technique) comes later." },
          { id: "r2", clue: "The newest tactic in v19, split from Defense Evasion: stopping the EDR service and turning auditing off. TA ID, please.", answer: "TA0112", why: "v19 split Defense Evasion in two. Stealth (TA0005) is about hiding. Defense Impairment (TA0112) is about breaking the defences themselves, like killing a sensor." },
          { id: "r3", clue: "An engineer jumps to the design server over Remote Desktop. Its parent technique is Remote Services, T1021. Give the sub-technique ID without the dot.", answer: "T1021001", why: "A technique is T plus four digits. The dot adds a variant: .001 is Remote Desktop Protocol. Without the dot it is T1021001, so the sub-technique always keeps its parent's four digits." },
          { id: "r4", clue: "An attacker tampers with the PLCs that run Marlow's wing-assembly line. Which ATT&CK matrix covers that, in three letters?", answer: "ICS", why: "Enterprise covers IT systems and cloud, Mobile covers phones, and ICS covers industrial control systems like PLCs. The IDs look the same but the matrix tells you which world they belong to." },
        ],
        lesson: "Read an ID in layers: TA is a goal, T plus four digits is a method, and a dot adds a variant. The matrix (Enterprise, Mobile, ICS) says which world the ID lives in.",
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
        kind: "duel",
        title: "Technique Against Control",
        prompt: "SILVER HERON, a fictional group for this exercise, is targeting aerospace suppliers. Jonah's ATT&CK Navigator coverage layer, the free tool that colours the matrix with your detections and a group's techniques, shows what Marlow already detects and what it does not. Each round the group plays a technique: play the control or detection that answers that exact technique. Each card can be used once.",
        attacker: "SILVER HERON",
        moves: [
          { id: "m1", move: "T1021.002 SMB/Windows Admin Shares", detail: "One design workstation copies a tool to the C$ share of eleven other workstations in ten minutes. Marlow has no rule for this technique.", counter: "smbseg", hint: "A foothold becoming fifty machines is the risk. Where does the traffic travel?", why: "Blocking workstation-to-workstation SMB and alerting on admin-share writes breaks Lateral Movement at its path. This blind spot is the first to fix, because one foothold turns into many." },
          { id: "m2", move: "T1482 Domain Trust Discovery", detail: "A non-admin workstation runs nltest /domain_trusts, once, at 02:10. Marlow has no rule for this technique.", counter: "trustrule", hint: "The command is a real admin tool. What differs is who runs it and from where.", why: "A process-creation rule on nltest with domain_trusts from non-admin hosts catches the Discovery step. Blocking the tool everywhere would break admins, so it is detection, not prevention." },
          { id: "m3", move: "T1003.001 LSASS Memory", detail: "A process opens lsass.exe with full access and writes a dump to Temp. EDR-LSASS-03 exists and fires.", counter: "lsaprot", hint: "The detection already works. What would make the dump fail?", why: "LSA protection and Credential Guard harden the process so the dump is useless or refused, which is a mitigation on top of the detection. Rotating passwords on a schedule does not stop an attacker reading memory." },
          { id: "m4", move: "T1567.002 Exfiltration to Cloud Storage", detail: "Marlow design files are uploaded to a personal cloud-storage account over HTTPS. DLP-CLOUD-02 exists but only watches known services.", counter: "cloudallow", hint: "Blocking all web traffic would stop the whole company.", why: "An allow-list of approved cloud services with upload alerts to anything else closes the gap that DLP misses. Blocking all outbound HTTPS would stop the business along with the theft." },
          { id: "m5", move: "T1059.001 PowerShell", detail: "powershell.exe -nop -w hidden -enc runs under a finance user on a Saturday. EDR-PS-ENC exists and fires.", counter: "psblock", hint: "The rule only tells you after the fact. What gives you the decoded content?", why: "Script block logging with constrained language mode gives you the decoded command and limits what it can do. Removing PowerShell breaks admin work that legitimately depends on it." },
        ],
        cards: [
          { id: "smbseg", name: "Block workstation SMB and alert on admin shares", effect: "Segments east-west file-sharing traffic." },
          { id: "trustrule", name: "Rule on nltest domain_trusts from non-admin hosts", effect: "Alerts when a normal user runs a trust query." },
          { id: "lsaprot", name: "LSA protection and Credential Guard", effect: "Hardens the process that holds credentials." },
          { id: "cloudallow", name: "Cloud-service allow-list with upload alerts", effect: "Permits approved services and flags the rest." },
          { id: "psblock", name: "Script block logging and constrained language mode", effect: "Records decoded scripts and limits what they can do." },
          { id: "rotate", name: "Quarterly password rotation", effect: "Forces every user to pick a new password." },
          { id: "blockhttps", name: "Block all outbound HTTPS", effect: "Stops web traffic from leaving the network." },
        ],
        lesson: "Threat-informed defence starts from the group's techniques, not from your tools. Fix uncovered techniques that spread access first, then pair detections with mitigations. Blanket controls break the business and still miss the technique.",
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
