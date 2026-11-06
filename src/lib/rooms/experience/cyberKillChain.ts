import type { RoomExperience } from "./types";

// "Operation Broken Link" for the "cyber-kill-chain" room.
// Script: docs/campaign/15-cyber-kill-chain.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Brightwater Utilities (fictional). Lab data differs from the graded tasks:
// the intrusion is an ISO/LNK loader with a Run-key foothold and DNS TXT C2,
// never q1's macro invoice, q3's 'WindowsUpdateHelper' scheduled task, or q2's
// and la1's 30-second HTTPS beacon to updates.microsoft-cdn-services.net /
// 91.92.248.115; the analogy match pairs bank-heist steps, not the stage list
// in order (o1); and the Diamond Model sheet never names the chain's
// limitations (q4).
export const CYBER_KILL_CHAIN: RoomExperience = {
  roomId: "cyber-kill-chain",
  codename: "Operation Broken Link",
  theme: "killchain",
  handler: { name: "Ayla Demir", role: "Threat Hunt Lead, Brightwater Utilities" },
  briefing: [
    "Brightwater Utilities. Water treatment for 1.2 million people, and an engineering network that must never go dark.",
    "At 09:47 this morning, a DNS sensor flagged one workstation asking the same strange domain the same question every five minutes.",
    "Ayla Demir leads threat hunting. She doesn't start with 'what is this?' She starts with 'how far along the chain did they get?'",
    "Walk the seven links, trace the intrusion back to its first email, and find where the chain breaks.",
  ],
  mission: "Learn the seven links of the Cyber Kill Chain, map a real intrusion onto them, hunt its foothold in the registry, trace it backwards from C2 to the email that delivered it, and frame it with the Diamond Model.",
  estimate: "~40 min",
  look: { primary: "#22d3ee", secondary: "#a78bfa", warn: "#f43f5e" },
  scene: "facilitychain",
  layout: "facility",
  story: {
    intro: { title: "Every Five Minutes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-intro-b86a8ce4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-intro-b3a9f9c7.jpg" },
    afterStation: {
      model: { title: "Seven Links", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch2-93429e05.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch2-ae172d89.jpg" },
      walk: { title: "Back to the First Email", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch3-342ffe1a.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch3-41357bde.jpg" },
      debrief: { title: "The Link That Broke", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-finale-3df53d22.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-finale-fca6e009.jpg" },
    },
  },
  stations: [
    {
      id: "model",
      label: "Seven Links",
      topic: "The Lockheed Martin Cyber Kill Chain · why breaking one link stops the attack",
      tagline: "See the chain through a bank heist, stage by stage",
      building: "archive",
      taskIds: ["ckc-r1"],
    },
    {
      id: "walk",
      label: "Walk the Chain",
      topic: "Reconnaissance to Actions on Objectives · what each stage looks like in evidence",
      tagline: "Map Brightwater's intrusion, then hunt its foothold",
      building: "lab",
      taskIds: ["ckc-r2", "ckc-q1", "ckc-q3"],
    },
    {
      id: "break",
      label: "Break the Chain",
      topic: "A control at every stage · defence in depth · hunting forward and backward",
      tagline: "Trace the intrusion from C2 back to its first email",
      building: "control",
      taskIds: ["ckc-r3", "ckc-q2", "ckc-la1"],
    },
    {
      id: "debrief",
      label: "The Debrief",
      topic: "The chain end to end · its limits · the Diamond Model beside it",
      tagline: "Put the whole story in order and know where the model stops",
      building: "ticket",
      taskIds: ["ckc-o1", "ckc-q4"],
      boss: true,
    },
  ],
  personas: {
    "ckc-q1": { name: "Ayla Demir", role: "Threat Hunt Lead", line: "Different case: an accountant enables macros. Which link is that?" },
    "ckc-q2": { name: "Ayla Demir", role: "Threat Hunt Lead", line: "Thirty-second heartbeat, all night, a few hundred bytes. Where are they?" },
    "ckc-q3": { name: "Ayla Demir", role: "Threat Hunt Lead", line: "A scheduled task that phones home at every boot. Which stage is creating it?" },
    "ckc-q4": { name: "Ayla Demir", role: "Threat Hunt Lead", line: "Last one. Where does this model fall short?" },
  },
  briefings: {
    // ── Reading 1: the model ──
    "ckc-r1": [
      {
        kind: "match",
        title: "The Heist Chain",
        prompt: "The reading compares an attack to a bank robbery. Match each step of the heist to the kill chain stage it plays. The seven-stage Cyber Kill Chain was developed by Lockheed Martin and published in 2011.",
        pairs: [
          { id: "recon", left: "Sitting in a café for a week, noting guard shifts and camera angles", right: "Reconnaissance", why: "Learning the target before touching it." },
          { id: "weapon", left: "Cloning a cleaner's keycard onto a blank card at home", right: "Weaponization", why: "Building the tool, still far from the target." },
          { id: "deliver", left: "Walking in through the staff entrance in a cleaner's uniform", right: "Delivery", why: "Getting the tool to where it will be used." },
          { id: "exploit", left: "The cloned card opens the vault-corridor door", right: "Exploitation", why: "The weakness is triggered: the system accepts the forgery." },
          { id: "install", left: "Wedging a fire door so the crew can come back tonight", right: "Installation", why: "A foothold that survives leaving and returning." },
          { id: "c2", left: "An earpiece linked to the driver outside, giving instructions", right: "Command and Control", why: "A channel to steer the operation from outside." },
          { id: "aoo", left: "Emptying the safe-deposit boxes", right: "Actions on Objectives", why: "What they came for. Everything before it was preparation." },
        ],
      },
    ],
    // ── Reading 2: the seven stages in evidence ──
    "ckc-r2": [
      {
        kind: "duel",
        title: "Break the Link",
        prompt: "Ayla replays Brightwater's intrusion one move at a time. For each move, play the control that breaks that exact link before the attacker reaches the next one. Each card can be used once.",
        attacker: "The Invoice_4471 operator",
        moves: [
          { id: "m1", move: "Delivery: a lookalike billing email", detail: "billing@brightwater-payments.example sends a link, not an attachment, to Invoice_4471.iso. The domain is nine days old.", counter: "mailgw", hint: "There is no attachment to open in a sandbox. What looks at the link and the sender's domain?", why: "A gateway that rewrites links and flags lookalike or newly registered domains stops Delivery. An attachment sandbox has nothing to inspect when the mail carries only a link. The sender name joins a real brand to an extra word (brightwater-payments): that is combosquatting. Typosquatting is different, a misspelling of the brand such as brightwatter.example." },
          { id: "m2", move: "Exploitation: the shortcut is double-clicked", detail: "j.okoro mounts the ISO as drive E:, opens the shortcut, and rundll32.exe loads inv.dll from that disc. No CVE is involved.", counter: "appctl", hint: "Nothing is unpatched. The user ran a legitimate binary with a hostile argument.", why: "Application control that blocks rundll32 from loading DLLs off a mounted image breaks Exploitation of trust. Patching cannot help, because no vulnerability was used." },
          { id: "m3", move: "Installation: a new Run value appears", detail: "A value named OneDriveSync is written to HKCU Run, pointing to a DLL in AppData Roaming through rundll32.", counter: "runmon", hint: "The foothold has to be written somewhere that survives a reboot.", why: "Alerting on new autostart values that launch rundll32 from a user profile catches Installation within seconds of the write. A signature scan sees nothing unusual in a registry string." },
          { id: "m4", move: "Command and Control: a beacon every five minutes", detail: "TXT lookups for a4f.telemetry-node42.example go out through the normal resolver, a nine-day-old domain.", counter: "dnsf", hint: "Blocking the port would break every lookup on the network.", why: "DNS filtering or a sinkhole for newly registered and C2-categorised domains cuts the beacon without breaking DNS. The implant then cannot receive instructions." },
          { id: "m5", move: "Actions on Objectives: data staged for theft", detail: "SCADA historian exports are zipped into C:\\ProgramData\\tmp and a large outbound transfer is queued.", counter: "egress", hint: "Everything before this has already happened. What stops the data leaving?", why: "Outbound transfer limits and alerts on bulk archive staging stop the objective itself. Encrypting the disk would not matter: the implant reads the files while the user is logged in." },
        ],
        cards: [
          { id: "mailgw", name: "Link rewriting and lookalike-domain filter", effect: "Checks sender domains and URLs at the mail gateway." },
          { id: "appctl", name: "Block rundll32 loading from mounted images", effect: "Application control on where code may load from." },
          { id: "runmon", name: "Alert on new Run values", effect: "Watches autostart locations for fresh entries." },
          { id: "dnsf", name: "DNS filtering and sinkhole", effect: "Blocks or redirects flagged names at the resolver." },
          { id: "egress", name: "Outbound limits and staging alerts", effect: "Flags large archives and big uploads." },
          { id: "sandbox", name: "Attachment sandbox", effect: "Detonates attached files before delivery." },
          { id: "patch", name: "Monthly patch cycle", effect: "Closes known software flaws on a schedule." },
        ],
        lesson: "Every control belongs to one link. Match the control to the stage's exact behaviour, such as a link instead of an attachment or a DLL loaded by a signed binary. A good control at the wrong link feels safe and breaks nothing.",
      },
      {
        kind: "pathway",
        title: "Walk the Chain",
        prompt: "Ayla pins every piece of evidence on the wall. Start at the first thing the attacker did and walk the evidence in the order the chain happened, forward to the objective. Some nodes are noise that looks right.",
        goal: "Walk Brightwater's intrusion from the first scrape to the staged data without skipping a link or following noise.",
        nodes: [
          { id: "scrape", label: "Staff list scraped", sub: "40 engineers", x: 12, y: 20 },
          { id: "iso", label: "ISO built", sub: "LNK and DLL", x: 34, y: 10 },
          { id: "mail", label: "Invoice link emailed", sub: "09:12 to j.okoro", x: 56, y: 24 },
          { id: "teams", label: "Teams missed-messages mail", sub: "08:02, clean", x: 38, y: 44 },
          { id: "click", label: "Shortcut double-clicked", sub: "rundll32 loads DLL", x: 80, y: 14 },
          { id: "defender", label: "Defender scheduled scan", sub: "09:44 MsMpEng", x: 82, y: 36 },
          { id: "runkey", label: "Run value written", sub: "OneDriveSync", x: 84, y: 58 },
          { id: "onedrive", label: "OneDrive Run value", sub: "OneDrive.exe", x: 66, y: 86 },
          { id: "beacon", label: "DNS TXT every 5 min", sub: "telemetry-node42", x: 36, y: 72 },
          { id: "zip", label: "Historian data zipped", sub: "ProgramData tmp", x: 12, y: 50 },
        ],
        edges: [
          ["scrape", "iso"], ["scrape", "mail"], ["iso", "mail"], ["iso", "click"], ["mail", "click"],
          ["mail", "teams"], ["click", "defender"], ["click", "runkey"], ["runkey", "onedrive"],
          ["runkey", "beacon"], ["runkey", "zip"], ["beacon", "zip"],
        ],
        route: ["scrape", "iso", "mail", "click", "runkey", "beacon", "zip"],
        notes: {
          scrape: "Reconnaissance: choosing targets from public profiles. The attacker has not touched Brightwater yet.",
          iso: "Weaponization: the ISO with a shortcut and a hidden DLL is built on the attacker's side, before anything is sent.",
          mail: "Delivery: a lookalike domain and a link, so the attachment scanner had nothing to inspect.",
          click: "Exploitation: j.okoro runs the shortcut and rundll32 loads the DLL. The attacker's code runs for the first time.",
          runkey: "Installation: the Run value OneDriveSync runs a DLL from Roaming through rundll32. The real value runs OneDrive.exe. Written at 09:41, one minute before the first beacon.",
          beacon: "Command and Control: TXT lookups exactly five minutes apart to a young domain, hidden among normal DNS.",
          zip: "Actions on Objectives: staging comes just before theft. Everything before it was preparation.",
        },
        traps: {
          mail: "Delivery needs a weapon first. The ISO has to be built before it can be sent, so Reconnaissance cannot lead straight to the email.",
          click: "The shortcut cannot be run before it arrives. Exploitation follows Delivery, so this hop skips a link.",
          teams: "A clean Teams notification at 08:02 is real mail with no link to an ISO. It is background traffic, not the delivery.",
          defender: "A scheduled Defender scan from svchost is routine. It happened to run during the incident but belongs to no stage.",
          onedrive: "This is the genuine OneDrive Run value running OneDrive.exe from its normal folder. The foothold is the value that borrows the name and loads a DLL.",
          zip: "Staging before a C2 channel exists would not be steered by anyone. Objectives come last, after the beacon is established.",
        },
        lesson: "Each link depends on the one before it: you cannot deliver an unbuilt weapon, install before code runs, or steer without a foothold. Beware benign look-alikes such as a genuine Run value or a scheduled scan.",
      },
    ],
    // ── Reading 3: breaking the chain ──
    "ckc-r3": [
      {
        kind: "trace",
        title: "Back Up the Chain",
        prompt: "Hunt backwards. Start at the C2 alert and follow each link to the one before it, until you reach the email.",
        lead: "09:47: the DNS sensor flagged WS-ENG-14 (10.40.12.88) for regular TXT lookups to a newly registered domain.",
        steps: [
          {
            id: "dns", source: "Zeek dns.log · WS-ENG-14 · 09:30-10:10",
            ask: "When did the beacon start? Click its first lookup.",
            columns: ["time", "query", "qtype", "answer"],
            rows: [["09:38:12", "login.microsoftonline.com", "A", "20.190.159.0"], ["09:42:05", "a4f.telemetry-node42.example", "TXT", "\"cmd=idle\""], ["09:44:51", "teams.microsoft.com", "A", "52.112.0.5"], ["09:47:05", "a4f.telemetry-node42.example", "TXT", "\"cmd=idle\""]],
            answer: 1,
            why: "TXT records carry text the implant reads as commands. The same subdomain is queried again at 09:47, exactly 5 minutes apart, starting 09:42.",
            learned: "C2: DNS TXT beacon every 5 min to telemetry-node42.example since 09:42",
          },
          {
            id: "reg", source: "Sysmon Event 13 (registry value set) · WS-ENG-14",
            ask: "Which change gave the implant a way to survive a reboot?",
            columns: ["time", "process", "target object", "details"],
            rows: [["09:15:40", "OneDrive.exe", "HKCU\\...\\OneDrive\\Accounts\\Business1\\LastSignIn", "DWORD 0x6729..."], ["09:41:33", "rundll32.exe", "HKCU\\...\\CurrentVersion\\Run\\OneDriveSync", "rundll32.exe \"...\\odsync\\odsync.dll\",Start"], ["09:52:10", "explorer.exe", "HKCU\\...\\Explorer\\RecentDocs", "(binary)"]],
            answer: 1,
            why: "A Run value written by rundll32 itself, one minute before the first beacon.",
            learned: "Installation: Run key OneDriveSync at 09:41",
          },
          {
            id: "proc", source: "Sysmon Event 1 (process create) · WS-ENG-14",
            ask: "Where did the attacker's code first run?",
            columns: ["time", "parent", "process", "command line"],
            rows: [["09:40:58", "explorer.exe", "rundll32.exe", "rundll32.exe E:\\data\\inv.dll,Start  (E: is the mounted Invoice_4471.iso)"], ["09:40:31", "explorer.exe", "Explorer (mount)", "Invoice_4471.iso mounted as drive E:"], ["09:44:02", "svchost.exe", "MsMpEng.exe", "(Defender scheduled scan)"]],
            answer: 0,
            why: "The shortcut on the mounted ISO ran a DLL from the same disc. The user's double-click triggered it: exploitation of trust, no CVE needed.",
            learned: "Exploitation: Invoice_4471.iso > shortcut > rundll32 inv.dll at 09:40",
          },
          {
            id: "mail", source: "Mail gateway · inbound to j.okoro · today",
            ask: "Which message delivered it?",
            columns: ["time", "from", "subject", "verdict"],
            rows: [["08:02", "noreply@teams.mail.microsoft", "You have 3 missed messages", "clean"], ["09:12", "billing@brightwater-payments.example", "Overdue invoice 4471: action needed", "clean (link only, no attachment)"], ["09:30", "h.ward@brightwater.example", "Pump station 6 schedule", "clean"]],
            answer: 1,
            why: "A lookalike billing domain with only a link, so the attachment scanner had nothing to inspect. The ISO was downloaded from the link.",
            learned: "Delivery: 09:12 email from brightwater-payments.example linking to the ISO",
          },
        ],
      },
    ],
    // Drill before the graded firewall record: the DNS beacon as a PAN-OS THREAT log.
    "ckc-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a PAN-OS Threat Log",
        prompt: "Before the graded record: how Brightwater's Palo Alto firewall logged the DNS beacon. Same log type, different C2 channel.",
        source: "PAN-OS · THREAT log · subtype spyware · DNS Security",
        fields: [
          { key: "type / subtype", value: "THREAT / spyware", label: "What kind", note: "DNS Security verdicts on C2 domains are logged as spyware." },
          { key: "src", value: "10.40.12.88", label: "Who", note: "WS-ENG-14." },
          { key: "dst", value: "10.40.0.10", label: "To", note: "The internal DNS resolver: the firewall saw the lookup on its way out." },
          { key: "app", value: "dns-base" },
          { key: "threatid", value: "Suspicious DNS Query (generic:a4f.telemetry-node42.example)", label: "Verdict", note: "What the DNS Security cloud thinks of the name." },
          { key: "category", value: "dns-c2", label: "Category", note: "Classified as command and control over DNS." },
          { key: "severity", value: "high" },
          { key: "action", value: "sinkhole", label: "What the firewall did", note: "Answered with a sinkhole address instead of the real one: the beacon now talks to nothing, and any host that tries shows up in the logs." },
          { key: "rule", value: "Outbound-DNS" },
        ],
        summary: "The beacon was cut at the C2 link by a DNS control, exactly where the defence matrix places it. Now read the graded record: same firewall family, a different channel.",
      },
    ],
    // Drill before q4: the Diamond Model beside the chain.
    "ckc-q4": [
      {
        kind: "worksheet",
        title: "The Diamond Beside the Chain",
        prompt: "The kill chain tells you when. The Diamond Model asks who, with what, against whom. Put Brightwater's case on its four corners. Note one limit of the chain: it models an outsider working through the stages, so an insider with authorised access, who can skip most early stages, fits it poorly.",
        caption: "Brightwater intrusion · Diamond Model worksheet",
        columns: ["evidence", "vertex"],
        rows: [
          ["telemetry-node42.example, brightwater-payments.example, 198.51.100.73", "?"],
          ["ISO with shortcut, rundll32 DLL loader, DNS TXT channel", "?"],
          ["WS-ENG-14, j.okoro, the engineering department", "?"],
          ["Unknown operator; same ISO builder seen in two other water utilities", "?"],
        ],
        questions: [
          { id: "infra", q: "Row 1, the domains and IP, sits on which vertex?", hint: "Adversary, Infrastructure, Capability, Victim.", answer: ["Infrastructure"], why: "What the attacker uses to deliver and control. Blocking it breaks C2 and Delivery." },
          { id: "cap", q: "Row 2, the tools and techniques?", hint: "What they can do.", answer: ["Capability"], why: "The ISO/LNK loader and the DNS channel are their capability, reusable across victims." },
          { id: "adv", q: "Row 4 points at which vertex?", hint: "Who is behind it.", answer: ["Adversary"], why: "The same builder at two other utilities hints at one operator targeting the sector: that's an intel lead, not a name." },
        ],
      },
    ],
  },
};
