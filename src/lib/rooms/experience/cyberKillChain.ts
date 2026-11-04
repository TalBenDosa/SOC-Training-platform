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
  scene: "chainlinks",
  layout: "stage",
  story: {
    intro: { title: "Every Five Minutes", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-intro-1606383a.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-intro-aff4213c.jpg" },
    afterStation: {
      model: { title: "Seven Links", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch2-3c6ca1ae.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch2-9b8c2808.jpg" },
      walk: { title: "Back to the First Email", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch3-fc864c1c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-ch3-2d2a2019.jpg" },
      debrief: { title: "The Link That Broke", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-finale-34bbaa9e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/cyber-kill-chain/brokenlink-finale-550c6150.jpg" },
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
        prompt: "The reading compares an attack to a bank robbery. Match each step of the heist to the kill chain stage it plays.",
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
        kind: "sort",
        title: "Map Brightwater's Intrusion",
        prompt: "What Ayla's team has pieced together so far, in no particular order. Put each finding on its link.",
        buckets: [
          { id: "recon", label: "Reconnaissance" },
          { id: "weapon", label: "Weaponization" },
          { id: "deliver", label: "Delivery" },
          { id: "exploit", label: "Exploitation" },
          { id: "install", label: "Installation" },
          { id: "c2", label: "Command and Control" },
          { id: "aoo", label: "Actions on Objectives" },
        ],
        items: [
          { id: "a", text: "40 Brightwater engineers' names and roles scraped from a professional network", bucket: "recon", why: "Picking targets: who works on what." },
          { id: "b", text: "An ISO image built containing a shortcut file and a hidden DLL", bucket: "weapon", why: "The weapon is assembled on the attacker's side, before anything is sent." },
          { id: "c", text: "Email from billing@brightwater-payments.example linking to Invoice_4471.iso", bucket: "deliver", why: "The weapon reaches the inbox." },
          { id: "d", text: "j.okoro double-clicks the shortcut; rundll32 loads the hidden DLL", bucket: "exploit", why: "The attacker's code first runs on the victim's machine." },
          { id: "e", text: "A Run key 'OneDriveSync' added so the implant starts at every logon", bucket: "install", why: "Persistence: the foothold survives a reboot." },
          { id: "f", text: "DNS TXT queries to a 9-day-old domain every 5 minutes", bucket: "c2", why: "The implant asks for instructions over DNS, hidden among normal lookups." },
          { id: "g", text: "SCADA historian exports zipped and staged in C:\\ProgramData\\tmp", bucket: "aoo", why: "Collecting what they came for. Staging comes just before theft." },
        ],
      },
      {
        kind: "terminal",
        title: "Hunt the Foothold",
        prompt: "WS-ENG-14 is j.okoro's workstation. Something there survives reboots. Find it the way responders do: check the autostart locations first.",
        shell: "cmd",
        host: "C:\\Users\\j.okoro>",
        commands: [
          { match: "reg\\s+query\\s+\"?hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\"?", help: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run     programs that start at this user's logon",
            output: "\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n    OneDrive    REG_SZ    \"C:\\Users\\j.okoro\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background\n    OneDriveSync    REG_SZ    rundll32.exe \"C:\\Users\\j.okoro\\AppData\\Roaming\\odsync\\odsync.dll\",Start\n" },
          { match: "dir\\s+.*odsync.*", help: "dir %APPDATA%\\odsync                                             what is in that folder, and since when",
            output: " Volume in drive C is OS\n Directory of C:\\Users\\j.okoro\\AppData\\Roaming\\odsync\n\n11/03/2026  09:41 AM    <DIR>          .\n11/03/2026  09:41 AM           412,160 odsync.dll\n               1 File(s)        412,160 bytes" },
          { match: "certutil\\s+-hashfile\\s+.*odsync\\.dll.*", help: "certutil -hashfile %APPDATA%\\odsync\\odsync.dll SHA256              hash it for threat intel",
            output: "SHA256 hash of C:\\Users\\j.okoro\\AppData\\Roaming\\odsync\\odsync.dll:\n4f1c9a2e77d0b8e5c3a1f6d2b9e8a7c4d5f60718293a4b5c6d7e8f9012345678\nCertUtil: -hashfile command completed successfully." },
        ],
        objectives: [
          { id: "val", task: "Which Run value is not the real OneDrive?", hint: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", answer: ["OneDriveSync"], why: "The real OneDrive runs OneDrive.exe. 'OneDriveSync' borrows the name but runs a DLL from a folder in Roaming through rundll32." },
          { id: "when", task: "When was the DLL written? (HH:MM AM/PM)", hint: "dir %APPDATA%\\odsync", answer: ["09:41 AM", "9:41 AM", "09:41", "9:41"], why: "09:41 on 3 November: one minute before the first DNS beacon. The foothold came right before C2." },
          { id: "stage", task: "Which kill chain stage is this Run key?", hint: "It makes the implant survive a reboot.", answer: ["Installation", "5", "stage 5"], why: "Installation: persistence. Removing it without cutting C2 and finding the delivery path only resets the clock." },
        ],
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
            ask: "Which lookups are the beacon?",
            columns: ["time", "query", "qtype", "answer"],
            rows: [["09:38:12", "login.microsoftonline.com", "A", "20.190.159.0"], ["09:42:05", "a4f.telemetry-node42.example", "TXT", "\"cmd=idle\""], ["09:44:51", "teams.microsoft.com", "A", "52.112.0.5"], ["09:47:05", "a4f.telemetry-node42.example", "TXT", "\"cmd=idle\""]],
            answer: 1,
            why: "TXT records carry text the implant reads as commands. The same subdomain, exactly 5 minutes apart, starting 09:42.",
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
        prompt: "The kill chain tells you when. The Diamond Model asks who, with what, against whom. Put Brightwater's case on its four corners.",
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
