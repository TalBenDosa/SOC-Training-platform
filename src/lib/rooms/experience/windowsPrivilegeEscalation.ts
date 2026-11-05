import type { RoomExperience } from "./types";

// "Operation Quiet Climb" for the "windows-privilege-escalation" room.
// Script: docs/campaign/32-windows-privilege-escalation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Ardent Rail (fictional), not the graded tasks' Meridian. Lab data differs
// from the graded tasks: the LSASS sort uses Sysmon 10 grants, never a failed
// 4656 request (q1); the hijack console is the eventvwr/mscfile variant read
// with reg query, never fodhelper, ms-settings or a Sysmon event ID (la1, f1,
// o1); the app-pool console shows a different site than q2's; the unquoted
// path console is a Rail Apps service, never Meridian Sync (q3); the jump
// sheet never contains ac1's installer; and nothing writes KQL (qf1) or pairs
// techniques with their signatures (m1).
export const WINDOWS_PRIVILEGE_ESCALATION: RoomExperience = {
  roomId: "windows-privilege-escalation",
  codename: "Operation Quiet Climb",
  theme: "privesc",
  handler: { name: "Priya Natarajan", role: "Threat Hunter, Ardent Rail" },
  briefing: [
    "Ardent Rail. 140 stations, a signalling network that must never stop, and 6,000 Windows endpoints from ticket machines to dispatch desks.",
    "A phishing foothold on a dispatch desk is a nuisance. The same foothold at High integrity, or as SYSTEM, can reach every credential on the box.",
    "Priya Natarajan hunts for the climb in between: the quiet step from Medium to High, and from a service account to SYSTEM.",
    "Learn to read integrity levels, LSASS access, UAC bypasses, impersonation and service misconfigurations, and to tell an approved elevation from a stolen one.",
  ],
  mission: "Read a process list by integrity level, sort LSASS access by who asked and for what, find a hijacked auto-elevate handler, check what an app-pool identity can impersonate, find an unquoted service path and a writable folder, and judge three Medium-to-High jumps.",
  estimate: "~55 min",
  look: { primary: "#f472b6", secondary: "#60a5fa", warn: "#f59e0b" },
  scene: "integrityladder",
  layout: "stage",
  stations: [
    {
      id: "levels",
      label: "Integrity Levels",
      topic: "Low, Medium, High, System · admin is not the same as elevated",
      tagline: "Read the column nobody looks at",
      building: "control",
      taskIds: ["privesc-r1"],
    },
    {
      id: "lsass",
      label: "Reaching LSASS",
      topic: "SeDebugPrivilege · access masks · LSA Protection and Credential Guard",
      tagline: "Who opened LSASS, and how far?",
      building: "vault",
      taskIds: ["privesc-r2", "privesc-q1"],
    },
    {
      id: "uac",
      label: "UAC Bypass",
      topic: "Auto-elevate binaries · the HKCU handler hijack",
      tagline: "Find the handler someone rewrote",
      building: "lab",
      taskIds: ["privesc-r3", "privesc-la1", "privesc-f1"],
    },
    {
      id: "system",
      label: "Road to SYSTEM",
      topic: "SeImpersonatePrivilege and Potatoes · unquoted paths · weak service ACLs",
      tagline: "From a service account to SYSTEM",
      building: "office",
      taskIds: ["privesc-r4", "privesc-q2", "privesc-r5", "privesc-q3"],
    },
    {
      id: "jump",
      label: "Read the Jump",
      topic: "Consent, auto-elevation or something else · hunting it fleet-wide",
      tagline: "Approved elevation or stolen one?",
      building: "ticket",
      taskIds: ["privesc-ac1", "privesc-m1", "privesc-o1", "privesc-qf1"],
      boss: true,
    },
  ],
  personas: {
    "privesc-q1": { name: "Priya Natarajan", role: "Threat Hunter", line: "A Medium process asked LSASS for everything and got refused. What does that tell you?" },
    "privesc-la1": { name: "Priya Natarajan", role: "Threat Hunter", line: "fodhelper parenting a High shell, and no consent prompt. Walk me through it." },
    "privesc-q2": { name: "Priya Natarajan", role: "Threat Hunter", line: "A web shell as an app-pool identity. How far is the attacker from SYSTEM?" },
    "privesc-q3": { name: "Priya Natarajan", role: "Threat Hunter", line: "A new Meridian.exe in Program Files, and an unquoted service path. Coincidence?" },
    "privesc-ac1": { name: "Priya Natarajan", role: "Threat Hunter", line: "Medium to High on a finance laptop. Stolen or approved?" },
  },
  briefings: {
    // ── Reading 1: integrity levels ──
    "privesc-r1": [
      {
        kind: "locks",
        title: "Four Integrity Doors",
        prompt: "DISP-DESK-11 has four doors, one per integrity level. Read each door's idea and the process behind it, then answer its check to open it.",
        locks: [
          {
            id: "low", letter: "L", name: "Low",
            idea: "Sandboxed: it can write almost nowhere.",
            example: "Edge's renderer process on DISP-DESK-11 runs at Low. Even a web page that fully owns it is stuck in its sandbox folder.",
            check: { q: "A malicious page fully controls the renderer. What can it overwrite?", options: ["Almost nothing outside its sandbox folder", "Any file m.osei can write"], answer: 0, why: "Low integrity can't write to objects at Medium or above, whatever the user's own rights." },
          },
          {
            id: "medium", letter: "M", name: "Medium",
            idea: "Everyday apps, even for administrators.",
            example: "DispatchBoard.exe runs at Medium although m.osei is a local admin: UAC keeps the full token in reserve.",
            check: { q: "Malware lands inside DispatchBoard.exe. Can it write HKLM straight away?", options: ["No, it has to reach High first", "Yes, because m.osei is an admin"], answer: 0, why: "Admin membership gives the ability to elevate, not elevation. The process is still Medium." },
          },
          {
            id: "high", letter: "H", name: "High",
            idea: "The full administrator token.",
            example: "Event Viewer (mmc.exe) on DISP-DESK-11 runs at High: it is one of the binaries that elevate for admins.",
            check: { q: "What is the normal way a process reaches High?", options: ["A consent prompt, or a binary built to auto-elevate", "Being started from explorer.exe"], answer: 0, why: "Explorer runs at Medium. High comes from consent or a trusted auto-elevating binary: which is exactly what attackers abuse." },
          },
          {
            id: "system", letter: "S", name: "System",
            idea: "The operating system itself.",
            example: "svchost.exe -k netsvcs runs as NT AUTHORITY\\SYSTEM, above every user on the box.",
            check: { q: "Who normally runs at System?", options: ["Services and core OS components", "Any member of Administrators"], answer: 0, why: "System belongs to the OS and its services. An attacker gets there through a service, a token, or a driver." },
          },
        ],
      },
    ],
    // ── Reading 2: LSASS ──
    "privesc-r2": [
      {
        kind: "sort",
        title: "Who Opened LSASS?",
        prompt: "Sysmon Event 10 on DISP-DESK-11 and two neighbours: every handle granted to lsass.exe in the last day. Tune on who asked, not just the mask.",
        buckets: [
          { id: "expected", label: "Expected: tune it out" },
          { id: "hunt", label: "Hunt it" },
        ],
        items: [
          { id: "defender", text: "MsMpEng.exe (Microsoft-signed, Program Files\\Windows Defender) · GrantedAccess 0x1410", bucket: "expected", why: "Defender scans LSASS routinely. Signed, expected path, expected mask." },
          { id: "procdump", text: "procdump64.exe from C:\\Users\\m.osei\\Downloads · GrantedAccess 0x1FFFFF", bucket: "hunt", why: "A dumping tool from a Downloads folder asking for everything. Full access was granted, so it was already elevated." },
          { id: "rundll", text: "rundll32.exe with comsvcs.dll, MiniDump in the command line · GrantedAccess 0x1410", bucket: "hunt", why: "A living-off-the-land dump. The mask looks modest; the command line gives it away." },
          { id: "edr", text: "CSFalconService.exe (CrowdStrike-signed) · GrantedAccess 0x1010", bucket: "expected", why: "The EDR sensor itself. Signed, known path." },
          { id: "unknown", text: "svc_health.exe, unsigned, from C:\\ProgramData\\Ardent · GrantedAccess 0x1010", bucket: "hunt", why: "0x1010 is enough to read credentials, and it's the mask Mimikatz-style tools use. Unsigned and unexplained: hunt it." },
        ],
      },
    ],
    // ── Reading 3: UAC bypass ──
    "privesc-r3": [
      {
        kind: "pathway",
        title: "Trace the Hijacked Handler",
        prompt: "On DISP-DESK-11 a High-integrity cmd.exe appeared under mmc.exe with no consent prompt. Priya wants the proof, in order. Walk the investigation from the alert to the fleet-wide hunt.",
        goal: "Prove how the elevation happened and scope it",
        nodes: [
          { id: "alert", label: "EDR alert", sub: "High cmd.exe under mmc.exe", x: 10, y: 84 },
          { id: "tree", label: "Process tree", sub: "parent, session, consent.exe", x: 28, y: 60 },
          { id: "hklm", label: "HKLM mscfile handler", sub: "machine-wide key", x: 14, y: 40 },
          { id: "uac", label: "UAC policy level", sub: "slider setting", x: 48, y: 40 },
          { id: "hkcu", label: "HKCU mscfile handler", sub: "the user's own hive", x: 46, y: 80 },
          { id: "script", label: "The handler script", sub: "lib.cmd contents", x: 66, y: 56 },
          { id: "reimage", label: "Reimage the desk", sub: "restore from gold image", x: 66, y: 16 },
          { id: "payload", label: "The payload", sub: "Public\\Libraries\\up.exe", x: 86, y: 82 },
          { id: "scope", label: "Fleet hunt", sub: "same key, same pattern", x: 86, y: 34 },
        ],
        edges: [["alert", "tree"], ["tree", "hklm"], ["tree", "uac"], ["tree", "hkcu"], ["hkcu", "script"], ["script", "reimage"], ["script", "payload"], ["payload", "scope"]],
        route: ["alert", "tree", "hkcu", "script", "payload", "scope"],
        notes: {
          alert: "Event Viewer (mmc.exe) auto-elevates by design, so mmc.exe at High is normal. What it launched is not: a command shell with no prompt.",
          tree: "Parent mmc.exe, started by explorer, and no consent.exe in the session. mmc opened a .msc file through its registered handler, so the next question is which handler it read.",
          hkcu: "Windows reads the user's own HKCU class key before the machine-wide one, and writing it needs no elevation. The default value points at C:\\Users\\Public\\Libraries\\lib.cmd instead of mmc.exe.",
          script: "lib.cmd saves the group list to a text file and starts up.exe. The saved list carries the High Mandatory Level label: the planted command ran elevated with no prompt.",
          payload: "up.exe sits in the same Public\\Libraries folder, which any user can write. Hash it, read its signature, and keep a copy before anything is removed.",
          scope: "Hunt fleet-wide for any per-user mscfile handler value and any High child of an auto-elevate binary with no consent.exe before it. One desk is the first sighting, not the whole story.",
        },
        traps: {
          hklm: "The machine-wide handler is untouched here, and it needs admin to change. The rewrite is in the user's own hive. Checking HKLM first shows a clean key and false comfort.",
          uac: "This bypass leaves the UAC setting alone: it abuses a binary that already auto-elevates, so the slider reads the same as on a healthy desk and proves nothing.",
          reimage: "Wiping now destroys the key, the script and the payload you need to prove how it worked and to hunt the other desks. Collect evidence first, then rebuild.",
        },
        lesson: "A bypass without a prompt leaves no consent.exe. Read the parent, then the per-user registry handler it consulted, then the script and payload behind it, and only then hunt for the same pattern fleet-wide.",
      },
    ],
    // ── Reading 4: impersonation ──
    "privesc-r4": [
      {
        kind: "rush",
        title: "Token Talk: True or False",
        prompt: "A web shell on WEB-TIX-02, the ticketing portal, is running as its app-pool identity and Priya is reading its token aloud. Call each statement about privileges and impersonation true or false before the clock runs out.",
        seconds: 60,
        target: 10,
        cards: [
          { id: "c1", text: "SeImpersonatePrivilege enabled on an app-pool identity is normal and by design.", answer: true, why: "Web apps need it to act as the users who connect. It is the precondition for a Potato-style climb, not an attack on its own." },
          { id: "c2", text: "A web shell running as an IIS app-pool identity is already SYSTEM.", answer: false, why: "App-pool accounts are virtual and low-privileged on purpose. The climb to SYSTEM is the part you are trying to detect." },
          { id: "c3", text: "With SeImpersonatePrivilege enabled the attacker is automatically SYSTEM.", answer: false, why: "The privilege only lets the process act as a client that connects to it. Something privileged must be coaxed into connecting first." },
          { id: "c4", text: "A running Print Spooler on a web server is one coercion path.", answer: true, why: "A spooler that can be made to connect to the attacker's endpoint hands over a SYSTEM token to impersonate. Ask why it is on at all." },
          { id: "c5", text: "Stopping the spooler on servers that never print removes that coercion path.", answer: true, why: "Reducing the attack surface is the cheap fix: if the service has no business purpose, disable it." },
          { id: "c6", text: "A privilege listed as Disabled in whoami /priv can never be used by that process.", answer: false, why: "Disabled means held but switched off. The process can enable it, so the list shows what the token may do, not only what it is doing." },
          { id: "c7", text: "SeChangeNotifyPrivilege enabled on an app pool is a red flag.", answer: false, why: "Bypass traverse checking is enabled for nearly every account by default. Learn the usual list so the unusual entries stand out." },
          { id: "c8", text: "NETWORK SERVICE and LOCAL SERVICE hold SeImpersonatePrivilege by default.", answer: true, why: "Service identities get it so they can act for clients, which is why a foothold in almost any service is worth checking for it." },
          { id: "c9", text: "Removing SeImpersonatePrivilege from the app pool is a safe fix with no side effects.", answer: false, why: "Services that impersonate callers can break without it. Test, and prefer fixing the exposure that lets a web shell run at all." },
          { id: "c10", text: "A child of w3wp.exe running as SYSTEM deserves an alert.", answer: true, why: "A web worker process should never have SYSTEM children. That parent-child shape is the sign the climb happened." },
          { id: "c11", text: "Running whoami /priv in the shell needs elevation and changes the system.", answer: false, why: "It only reads the token the process already holds. Attackers run it first, so seeing it in a w3wp.exe tree is a useful signal." },
          { id: "c12", text: "Membership in Administrators means every program a user starts runs at High.", answer: false, why: "UAC keeps administrators at Medium until a prompt or an auto-elevating binary raises a process." },
          { id: "c13", text: "A Medium-integrity process owned by an administrator can write HKLM straight away.", answer: false, why: "It must reach High first. Admin membership gives the ability to elevate, not elevation." },
          { id: "c14", text: "A virtual app-pool account looks like iis apppool followed by the pool name.", answer: true, why: "That name pattern in a process tree tells you the code is the web application itself, not a logged-on person." },
        ],
        lesson: "Read the token before you read the exploit: who the account is, which privileges it holds (and whether they are enabled), and what service exposure would let it reach SYSTEM.",
      },
    ],
    // ── Reading 5: unquoted paths and weak ACLs ──
    "privesc-r5": [
      {
        kind: "pathway",
        title: "The Path With Spaces",
        prompt: "SIG-MON-04 monitors trackside signals. A service there starts from a path with spaces and no quotes. Walk the way Windows resolves it, and the way you prove the weakness, one hop at a time.",
        goal: "Prove which file will run as SYSTEM at the next start",
        nodes: [
          { id: "sweep", label: "Service sweep", sub: "Name, PathName, StartName", x: 10, y: 80 },
          { id: "quoted", label: "ArdentTelemetry", sub: "quoted, Program Files", x: 12, y: 44 },
          { id: "unq", label: "SigMonAgent", sub: "unquoted, LocalSystem", x: 34, y: 82 },
          { id: "real", label: "The real binary", sub: "...\\bin\\sigmon.exe", x: 36, y: 46 },
          { id: "c1", label: "C:\\Rail.exe", sub: "first candidate", x: 56, y: 62 },
          { id: "rootacl", label: "ACL on C:\\", sub: "root of the drive", x: 82, y: 50 },
          { id: "acl", label: "ACL on C:\\Rail Apps", sub: "who may write here", x: 80, y: 84 },
          { id: "planted", label: "C:\\Rail Apps\\Signal.exe", sub: "second candidate", x: 60, y: 28 },
          { id: "fix", label: "Contain and fix", sub: "quote path, tighten ACL", x: 88, y: 18 },
        ],
        edges: [["sweep", "quoted"], ["sweep", "unq"], ["unq", "real"], ["unq", "c1"], ["c1", "rootacl"], ["c1", "acl"], ["acl", "planted"], ["planted", "fix"]],
        route: ["sweep", "unq", "c1", "acl", "planted", "fix"],
        notes: {
          sweep: "List every service's binary path and account, and filter out the Windows folder. You are looking for a path with spaces and no quotes, running as a strong account.",
          unq: "SigMonAgent: C:\\Rail Apps\\Signal Monitor\\bin\\sigmon.exe, no quotes, two spaces, LocalSystem. Windows may try each shorter name before the full path.",
          c1: "Windows cuts at the first space and tries C:\\Rail.exe first, then C:\\Rail Apps\\Signal.exe, then the real file. The first candidate needs write access to the root of the drive, which ordinary users lack.",
          acl: "icacls shows BUILTIN\\Users with Write on C:\\Rail Apps. Any user can drop a file there, which makes the second candidate the exposed one.",
          planted: "dir shows a Signal.exe written at 01:40, which is not part of the install. At the next service start it runs as SYSTEM.",
          fix: "Quote the ImagePath, remove write access for Users on the folder, preserve and hash the file, and hunt for the same product on other signal monitors.",
        },
        traps: {
          quoted: "A quoted path is resolved exactly as written, so spaces create no alternate candidates, and Program Files needs admin to write. A decoy that looks like the finding.",
          real: "The real binary is the last file Windows tries. The weakness is in the candidates it tries before it, so start from the first shorter name.",
          rootacl: "On C:\\ ordinary users may add folders but not files, so nobody can plant C:\\Rail.exe. The writable spot is the folder of the second candidate.",
        },
        lesson: "An unquoted service path gives Windows a list of guesses. The risk is the first guess a normal user can write, so check each candidate and the ACL on its folder, then fix the quoting and the permissions together.",
      },
    ],
    // ── Boss: three jumps before the graded verdict ──
    "privesc-ac1": [
      {
        kind: "worksheet",
        title: "Three Jumps",
        prompt: "Three Medium-to-High jumps from Ardent's dispatch floor this week. For each, look for the evidence that explains it.",
        caption: "Sysmon 1 · IntegrityLevel High · parent at Medium · Ardent Rail",
        columns: ["host", "child (High)", "parent", "consent.exe in session?", "record"],
        rows: [
          ["DISP-DESK-03", "TimetableSetup.msi via msiexec.exe", "explorer.exe", "yes, 3 s earlier", "Intune app assignment ITA-778"],
          ["DISP-DESK-07", "powershell.exe -nop -w hidden", "sdclt.exe", "no", "none"],
          ["DISP-DESK-11", "mmc.exe eventvwr.msc", "explorer.exe", "no", "user opened Event Viewer from Start"],
        ],
        questions: [
          { id: "odd", q: "Which host needs an incident ticket?", hint: "No prompt, no record, and a parent that shouldn't launch shells.", answer: ["disp-desk-07"], why: "sdclt.exe is another auto-elevate binary. Launching a hidden PowerShell with no prompt and no record is the bypass pattern." },
          { id: "why11", q: "DISP-DESK-11 has no consent prompt either. Why is it fine?", hint: "Which binary is the High process?", answer: ["auto-elevate", "auto elevate", "autoelevate", "mmc auto-elevates", "event viewer auto-elevates", "it auto-elevates"], why: "mmc.exe for Event Viewer auto-elevates by design and was started by the user from explorer. What it launches next is what you'd watch." },
        ],
      },
    ],
  },
};
