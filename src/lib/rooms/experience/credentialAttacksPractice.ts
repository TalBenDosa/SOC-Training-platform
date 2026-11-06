import type { RoomExperience } from "./types";
import type { HuntTable } from "./hunt";

// "Operation Spray Paint" for the "credential-attacks-practice" room.
// Script: docs/campaign/85-credential-attacks-practice.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Mariposa Hotels Group (fictional), not the graded tasks' Vantree records.
// Signature: Tell the Attacks Apart by Their Shape. Two KQL hunts on one table: From Failures
// to Breadth turns raw failures into distinct accounts per source, Prove a Success Followed joins
// on account plus source and checks the time. Name the Shape From the Numbers (sort) then calls
// spray, stuffing and brute force from numbers alone. Room 62 owns the sliding-count tune, so
// nothing here tunes a dial.
// Game mix: hunt + intercept + spotdiff.
//
// TASK ORDER CHANGED: r1, r2, q1, m1 | la1, la2, f1, q2 | ac1, o1 | qf1.
// f1 moved from after qf1 to straight after la2, because it reads the la2 record. Its text says
// "Log Analysis 2", and that still holds: la1 and la2 keep their order and stay the only two.
//
// Lab data differs from the graded tasks: the hunts use IdentityLogonEvents with ActionType and
// AccountName, never SecurityEvent, EventID or TargetUserName (qf1), and count breadth with two
// summarize lines, not dcount; 9 accounts from a training-room PC at policy 6, never 142 at policy
// 4 from an external IP (la2); 14 failures on a conference login, never 47 on a named user (la1);
// the lockout worksheet never shows a run that flips to a lock code (q1); the benign cases are a
// credentialed scan, a phone mail app and a red team, never a service account after a password
// change (ac1); After the Hit is a stuffing takeover ending in payroll, never a spray ending on a
// file server (o1); the window and bar are 3h and 6 on a 37-account spray (qf1).

const atLeast = (n: number) => Array.from({ length: 100 - n }, (_, i) => String(n + i));
/** What `Timestamp > ago(...)` keeps at 07:10 on 11-06. */
const since = (t: string) => NIGHT.rows.map(r => r[0]).filter(ts => ts >= t);

/** The same night, used by both hunts, so what one finds the other can prove. */
const NIGHT: HuntTable = {
  name: "IdentityLogonEvents",
  note: "Sign-ins seen by Defender for Identity.",
  columns: ["Timestamp", "ActionType", "AccountName", "IPAddress", "DeviceName", "Application"],
  rows: [
    ["11-03 14:05", "LogonFailed", "l.santos", "10.60.1.5", "MH-IT-AUDIT01", "Active Directory"],
    ["11-03 14:05", "LogonFailed", "v.gomes", "10.60.1.5", "MH-IT-AUDIT01", "Active Directory"],
    ["11-03 14:05", "LogonFailed", "t.dias", "10.60.1.5", "MH-IT-AUDIT01", "Active Directory"],
    ["11-03 14:06", "LogonFailed", "b.nunes", "10.60.1.5", "MH-IT-AUDIT01", "Active Directory"],
    ["11-03 14:06", "LogonFailed", "e.faria", "10.60.1.5", "MH-IT-AUDIT01", "Active Directory"],
    ["11-03 14:06", "LogonFailed", "g.moura", "10.60.1.5", "MH-IT-AUDIT01", "Active Directory"],
    ["11-03 14:07", "LogonFailed", "d.matos", "10.60.1.5", "MH-IT-AUDIT01", "Active Directory"],
    ["11-05 10:02", "LogonSuccess", "a.pinto", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-05 10:03", "LogonSuccess", "r.sousa", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-05 14:20", "LogonSuccess", "f.marques", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-05 22:58", "LogonFailed", "k.almeida", "10.60.4.12", "MH-LIS-FD02", "Active Directory"],
    ["11-05 22:59", "LogonSuccess", "k.almeida", "10.60.4.12", "MH-LIS-FD02", "Active Directory"],
    ["11-05 23:01", "LogonFailed", "j.cardoso", "10.60.4.12", "MH-LIS-FD02", "Active Directory"],
    ["11-05 23:01", "LogonSuccess", "j.cardoso", "10.60.4.12", "MH-LIS-FD02", "Active Directory"],
    ["11-05 23:04", "LogonSuccess", "f.marques", "10.60.4.31", "MH-LIS-NA01", "Active Directory"],
    ["11-05 23:12", "LogonFailed", "p.vieira", "10.60.7.20", "MH-POR-FD01", "Active Directory"],
    ["11-05 23:13", "LogonSuccess", "p.vieira", "10.60.7.20", "MH-POR-FD01", "Active Directory"],
    ["11-05 23:20", "LogonFailed", "h.costa", "10.60.7.20", "MH-POR-FD01", "Active Directory"],
    ["11-06 01:15", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:17", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:19", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:21", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:23", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:25", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:27", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:29", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:31", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:33", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:35", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:37", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:39", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 01:41", "LogonFailed", "conf.salonazul", "10.60.31.77", "-", "Active Directory"],
    ["11-06 02:04", "LogonFailed", "a.pinto", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:05", "LogonFailed", "r.sousa", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:05", "LogonFailed", "c.rocha", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:06", "LogonFailed", "f.marques", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:06", "LogonFailed", "n.tavares", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:07", "LogonFailed", "o.reis", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:07", "LogonFailed", "u.simoes", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:08", "LogonFailed", "s.barros", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 02:08", "LogonFailed", "h.teixeira", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 03:26", "LogonFailed", "a.pinto", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 03:26", "LogonFailed", "r.sousa", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 03:26", "LogonFailed", "c.rocha", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 03:27", "LogonSuccess", "f.marques", "10.60.12.40", "MH-LIS-TRAIN01", "Active Directory"],
    ["11-06 04:02", "LogonFailed", "t.fonseca", "203.0.113.11", "-", "Staff Portal"],
    ["11-06 04:05", "LogonFailed", "w.machado", "203.0.113.29", "-", "Staff Portal"],
    ["11-06 04:07", "LogonFailed", "z.pires", "203.0.113.47", "-", "Staff Portal"],
    ["11-06 04:10", "LogonFailed", "y.brito", "203.0.113.63", "-", "Staff Portal"],
    ["11-06 04:11", "LogonSuccess", "s.ferreira", "203.0.113.63", "-", "Staff Portal"],
    ["11-06 04:15", "LogonFailed", "q.antunes", "203.0.113.88", "-", "Staff Portal"],
    ["11-06 04:19", "LogonFailed", "x.leal", "203.0.113.102", "-", "Staff Portal"],
    ["11-06 06:52", "LogonSuccess", "a.pinto", "10.60.4.18", "MH-LIS-FD01", "Active Directory"],
    ["11-06 06:58", "LogonFailed", "i.ramos", "10.60.4.12", "MH-LIS-FD02", "Active Directory"],
    ["11-06 06:59", "LogonSuccess", "i.ramos", "10.60.4.12", "MH-LIS-FD02", "Active Directory"],
  ],
};

export const CREDENTIAL_ATTACKS_PRACTICE: RoomExperience = {
  roomId: "credential-attacks-practice",
  codename: "Operation Spray Paint",
  theme: "spraypaint",
  handler: { name: "Ewan Tshabalala", role: "Detection Analyst, Mariposa Hotels Group" },
  briefing: [
    "Mariposa Hotels Group. 38 hotels, 7,400 staff, one domain, and every front desk signs in against the same two domain controllers.",
    "At 07:10 on Friday the failed-logon wall in the Lisbon SOC is red from end to end, three days before the group's owners arrive for their annual summit.",
    "Ewan Tshabalala does not believe the rule titles on that wall. Each attack up there needs a different response, and one of them may already have worked.",
    "Learn the shapes, write the query that proves them, find out whether a guess landed, and leave a rule behind that sees it next time.",
  ],
  mission: "Separate sign-in attacks from memory theft, read a 4625 field by field, turn raw failures into accounts per source, name each shape from its numbers, prove whether a guess landed, explain the bursts that are harmless, then write the detection.",
  estimate: "~55 min",
  look: { primary: "#ff5fa8", secondary: "#6ee7ff", warn: "#ffc24b" },
  scene: "facilityspraypaint",
  layout: "facility",
  stations: [
    {
      id: "wall",
      label: "The Wall",
      topic: "Four credential techniques · Event 4625 fields · Status and SubStatus · grouping by account and by source",
      tagline: "Every attack leaves the same red",
      building: "control",
      taskIds: ["cred-r1", "cred-r2", "cred-q1", "cred-m1"],
    },
    {
      id: "shape",
      label: "The Shape",
      topic: "Brute force and spraying in raw records · lockout thresholds · proving a success",
      tagline: "Deep or wide, and did it land?",
      building: "lab",
      taskIds: ["cred-la1", "cred-la2", "cred-f1", "cred-q2"],
    },
    {
      id: "after",
      label: "After the Burst",
      topic: "Bursts with an honest cause · verdicts · what follows a success",
      tagline: "Explain it, or follow it",
      building: "office",
      taskIds: ["cred-ac1", "cred-o1"],
    },
    {
      id: "detection",
      label: "The Detection",
      topic: "Writing a spray detection in KQL",
      tagline: "Leave a rule behind",
      building: "ticket",
      taskIds: ["cred-qf1"],
      boss: true,
    },
  ],
  personas: {
    "cred-q1": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "Same account, and the code changed partway through. Talk me through it." },
    "cred-m1": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "Put a name to each pattern. Leave the rule titles out of it." },
    "cred-la1": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "One record on the screen. Read what sits behind it." },
    "cred-la2": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "Another day, another record. Same discipline." },
    "cred-f1": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "I only need one number from that record." },
    "cred-q2": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "Two findings landed together. Tell me which is which." },
    "cred-ac1": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "The rule fired. What goes on the ticket?" },
    "cred-o1": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "Walk me through how it plays out, start to finish." },
    "cred-qf1": { name: "Ewan Tshabalala", role: "Detection Analyst", line: "This one goes live tonight. Fill it in." },
  },
  briefings: {
    // ── Reading 1: four techniques, one symptom ──
    "cred-r1": [
      {
        kind: "sort",
        title: "Does It Touch a Sign-In at All?",
        prompt: "Ewan's first question about anything on the wall: did this ask a domain controller to check a password? Sort each activity. If it did, a failed logon can exist. If it did not, you are in the wrong log.",
        primer: {
          title: "Four techniques, three questions",
          points: [
            "**Brute force (T1110.001):** many passwords against one account.",
            "**Password spraying (T1110.003):** one or two common passwords against many accounts, thin enough that no account locks.",
            "**Credential stuffing (T1110.004):** no guessing. Username and password pairs stolen in another breach are replayed, so each account usually sees one attempt, from many addresses.",
            "**OS credential dumping (T1003):** secrets are read from memory or from a file on a host. Nothing asks a domain controller to check a password, so no failed logon is written.",
            "Three questions sort them: how many accounts, how many attempts each, and did it touch a sign-in at all? A rule's title only says what its author hoped to catch.",
          ],
          example: {
            label: "The same four, on hotel room safes",
            lines: [
              "Forty codes tried on one guest's safe: deep, one target.",
              "The code 0000 tried once on every safe on the floor: wide and thin.",
              "Codes bought from a breach at another hotel, tried once per guest: no guessing at all.",
              "The master list copied from the manager's drawer: no safe was ever touched.",
            ],
          },
        },
        buckets: [
          { id: "auth", label: "Asks for a sign-in" },
          { id: "host", label: "No sign-in at all" },
        ],
        items: [
          { id: "s1", text: "A script walks a long wordlist against one conference-room login", bucket: "auth", why: "Every guess is a password check, so every wrong guess can leave a failed logon." },
          { id: "s2", text: "rundll32 comsvcs.dll MiniDump against the lsass.exe process", bucket: "host", why: "T1003.001. It copies LSASS memory to a file. The evidence is process access on that host." },
          { id: "s3", text: "Pairs leaked from a travel site tried at the staff portal", bucket: "auth", why: "Stolen pairs still have to be presented at a sign-in, so the portal's log records them." },
          { id: "s4", text: "reg save HKLM\\SAM on a night audit PC", bucket: "host", why: "T1003.002. It copies a credential store to a file. Nothing was logged on to." },
          { id: "s5", text: "One common password tried once on every account in the Porto hotel", bucket: "auth", why: "Thin, but each try is still a sign-in, and each wrong one is a failed logon." },
          { id: "s6", text: "ntds.dit copied out of a volume shadow copy on a domain controller", bucket: "host", why: "T1003.003. The domain's password database is read as a file. No password is ever checked." },
          { id: "s7", text: "Sysmon Event ID 10: TargetImage lsass.exe, GrantedAccess 0x1010", bucket: "host", why: "Sysmon's process access event, one process opening LSASS with rights to read its memory. This lives in host telemetry." },
          { id: "s8", text: "Twenty guessed usernames tried with one password each", bucket: "auth", why: "A guessed name is still a sign-in attempt. It simply fails with a different code, which comes up next." },
        ],
      },
    ],
    // ── Reading 2: the fields of a 4625, and the two axes ──
    "cred-r2": [
      {
        kind: "spotdiff",
        title: "A Typo Beside a Script: What Actually Differs",
        prompt: "Two 4625 records from Thursday night. One is a receptionist mistyping at shift change. The other came from a script. The outcome fields match perfectly, so the outcome can't tell them apart. Tap the fields that can.",
        primer: {
          title: "Reading Event ID 4625, a failed logon",
          points: [
            "`TargetUserName` is the account tried. `IpAddress` and `WorkstationName` say where the attempt came from.",
            "`LogonType` says what kind of session was asked for: 2 at the keyboard, 3 over the network, 5 a service starting, 10 remote desktop.",
            "`LogonProcessName` and `AuthenticationPackageName` say which part of Windows handled it. A keyboard logon goes through User32. A scripted network logon often shows NtLmSsp.",
            "`Status` and `SubStatus` are the outcome. `FailureReason` (often %%2313) repeats it and adds nothing.",
            "One record is one data point. These fields describe how the attempt was made, not whether it was hostile.",
          ],
          example: {
            label: "One worked record",
            lines: [
              "`LogonType: 10`, `IpAddress: 10.8.3.9`, `WorkstationName: IT-JUMP2`",
              "Read it as: someone tried remote desktop from IT-JUMP2. Who, and whether that's normal, needs more than this line.",
            ],
          },
        },
        goodTitle: "22:58 · front desk PC, shift change",
        suspectTitle: "02:04 · the script",
        good: [
          "EventID: 4625",
          "TimeCreated: 2026-11-05T22:58:14Z",
          "Computer: MH-LIS-FD02.mariposa.example",
          "TargetUserName: k.almeida",
          "TargetDomainName: MARIPOSA",
          "Status: 0xC000006D",
          "SubStatus: 0xC000006A",
          "FailureReason: %%2313",
          "LogonType: 2",
          "WorkstationName: MH-LIS-FD02",
          "IpAddress: 127.0.0.1",
          "LogonProcessName: User32",
          "AuthenticationPackageName: Negotiate",
        ],
        suspect: [
          "EventID: 4625",
          "TimeCreated: 2026-11-06T02:04:51Z",
          "Computer: MH-DC01.mariposa.example",
          "TargetUserName: a.pinto",
          "TargetDomainName: MARIPOSA",
          "Status: 0xC000006D",
          "SubStatus: 0xC000006A",
          "FailureReason: %%2313",
          "LogonType: 3",
          "WorkstationName: -",
          "IpAddress: 10.60.12.40",
          "LogonProcessName: NtLmSsp",
          "AuthenticationPackageName: NTLM",
        ],
        diffs: [
          { line: 8, why: "Type 2 is hands on a keyboard. Type 3 is a network logon: no session to set up, so it's cheap to script at volume." },
          { line: 9, why: "A person's PC fills in its name. Many tools send nothing or a made-up name. That's a clue rather than proof, so read it with the rest." },
          { line: 10, why: "127.0.0.1 means the attempt began on that machine. Here a real address names a source you can group on." },
          { line: 11, why: "User32 is the Windows sign-in screen. NtLmSsp means the request came in over the network." },
          { line: 12, why: "Negotiate lets Windows pick Kerberos first. A direct NTLM request is what most network tooling sends. Fine alone, telling beside type 3 and an empty workstation name." },
        ],
        decoys: [
          { line: 1, why: "02:00 proves nothing: night auditors work at that hour in every hotel. Time helps only once you have a shape." },
          { line: 2, why: "A record sits on whichever machine refused the logon. This one was refused at a domain controller. That's where it landed, not how it was made." },
          { line: 3, why: "Any account can be a target and anyone can mistype. The name doesn't separate a typo from a script." },
        ],
        hud: "Tap the fields that show a script, not a person",
        sameLine: "That line matches in both copies. A typo and a wrong guess end in the same outcome codes, so these fields can't separate them.",
        winTitle: "Five fields found",
        howTo: ["Read the two records side by side.", "Tap a line in the right-hand copy if it shows how the attempt was made.", "Different isn't always meaningful: three lines differ and prove nothing."],
        lesson: "The outcome tells you what happened to the attempt. How it was made lives in LogonType, the logon process, the package and the source. Even those only raise a question: one record is never a verdict.",
      },
      {
        kind: "worksheet",
        title: "Read the Outcome Code",
        prompt: "Ewan keeps this code card taped to the side of the wall. Status gives the outcome, and SubStatus narrows it. Use the card to read two situations from the Porto hotel.",
        caption: "Event ID 4625 · Status and SubStatus · Ewan's code card",
        columns: ["Status", "SubStatus", "Means", "Describes"],
        rows: [
          ["0xC000006D", "0xC000006A", "Account exists, wrong password", "the guess"],
          ["0xC000006D", "0xC0000064", "Username does not exist", "the guess"],
          ["0xC0000234", "0x0", "Account is locked out", "the account, not the guess"],
          ["0xC000006E", "0xC0000071", "Password has expired", "the account, not the guess"],
        ],
        questions: [
          { id: "names", q: "Two hundred names tried from one address in Porto, SubStatus 0xC0000064 on all of them. What is being guessed: usernames or passwords?", hint: "Read the Means column for that SubStatus.", answer: ["usernames", "username", "names"], why: "The names don't exist, so the attacker doesn't yet know who works there. A strong tell: real staff rarely mistype into a name that was never issued." },
          { id: "expired", q: "A housekeeper's logon returns Status 0xC000006E with SubStatus 0xC0000071. Does that row say the password typed was wrong? (yes/no)", hint: "Look at the Describes column.", answer: ["no", "n"], why: "This row describes the account, not the guess. Some codes report what was typed, others report something about the account itself. Read which kind you have before you draw a conclusion." },
        ],
      },
      {
        kind: "hunt",
        title: "From Failures to Breadth",
        prompt: "It's 07:10 on Friday. The wall counts failures, and failures alone can't name an attack. Build the query Ewan wants, one line at a time: from raw failures to how many different accounts each source touched. Every result is what that line really returns.",
        primer: {
          title: "Counting accounts, not attempts",
          points: [
            "`IdentityLogonEvents` is the Defender for Identity table. `ActionType` is `LogonFailed` or `LogonSuccess`, `AccountName` is the account tried, `IPAddress` is the source. Windows writes the same moments as 4625 and 4624 on the machine that refused or accepted the logon.",
            "`ago(2d)` means two days before now, so `where Timestamp > ago(2d)` keeps the last two days.",
            "`summarize attempts = count() by A, B` gives one row per pair of A and B, with a count on it.",
            "Summarize that result again by A and you count its rows, which is how many different B values each A touched. In one line, `dcount(B)` gives a close estimate of the same number.",
          ],
          example: {
            label: "Same method, other data: who opened the most different rooms?",
            lines: [
              "`KeyCardEvents | summarize opens = count() by StaffId, Room`: one row per person and room.",
              "`| summarize rooms = count() by StaffId`: how many different rooms each person opened.",
              "kc-114: 31 rooms. kc-208: 2 rooms, though kc-208 had more door opens in total. Volume and breadth are different questions.",
              "One line: `| summarize rooms = dcount(Room) by StaffId`.",
            ],
          },
        },
        language: "KQL",
        start: "IdentityLogonEvents",
        goal: "one row: the source that touched too many accounts",
        tables: [NIGHT],
        rungs: [
          {
            id: "fail", ask: "Line 2: the table holds successes too. Keep only the failures.",
            choices: [
              { id: "a", text: '| where ActionType contains "Logon"', why: "Every row in this table has Logon in it, so nothing was filtered: 55 rows, successes included.", apply: { op: "where", col: "ActionType", test: "has", value: "Logon" } },
              { id: "b", text: '| where ActionType == "LogonFailed"', right: true, why: "44 failures. This is the raw pile the wall is counting.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonFailed" } },
              { id: "c", text: '| where ActionType == "LogonSuccess"', why: "Those are the successes, and you want the attempts that failed. Successes come later, when you test whether anything landed.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonSuccess" } },
            ],
          },
          {
            id: "time", ask: "Line 3: it's 07:10, and Ewan wants last night only.",
            choices: [
              { id: "a", text: "| where Timestamp > ago(1h)", why: "One row, a typo at 06:58. A window shorter than the attack cuts the attack out: nothing from 01:00 to 04:30 survives.", apply: { op: "where", col: "Timestamp", test: "in", value: since("11-06 06:10") } },
              { id: "b", text: "| where Timestamp > ago(7d)", why: "Tuesday's approved password audit from MH-IT-AUDIT01 is back in. Its seven accounts would sit beside last night's activity as if they belonged together. Too wide a window lets old breadth pile up.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonFailed" } },
              { id: "c", text: "| where Timestamp > ago(12h)", right: true, why: "37 rows, from 19:10 yesterday. Long enough to hold the whole night, short enough to keep Tuesday out.", apply: { op: "where", col: "Timestamp", test: "in", value: since("11-05 19:10") } },
            ],
          },
          {
            id: "pair", ask: "Line 4: reduce the pile to one row for each account a source tried.",
            choices: [
              { id: "a", text: "| summarize attempts = count() by IPAddress", why: "Raw volume per source. 10.60.31.77 tops the list with 14, and it only ever tried one account. Volume alone can't tell you which is which.", apply: { op: "summarize", by: ["IPAddress"], as: "attempts" } },
              { id: "b", text: "| summarize attempts = count() by AccountName", why: "That's the other axis: how hard each account was hit, whoever hit it. Good for spotting a deep attack, but the source is gone, and the source is what you need next.", apply: { op: "summarize", by: ["AccountName"], as: "attempts" } },
              { id: "c", text: "| summarize attempts = count() by IPAddress, AccountName", right: true, why: "21 rows, one per source and account. Repeat tries on the same account now collapse into a single row.", apply: { op: "summarize", by: ["IPAddress", "AccountName"], as: "attempts" } },
            ],
          },
          {
            id: "breadth", ask: "Line 5: each row is now one account touched. Turn that into accounts per source.",
            choices: [
              { id: "a", text: "| summarize accounts = count() by IPAddress", right: true, why: "10 sources. 10.60.12.40, a training-room PC, touched 9 accounts. 10.60.31.77 had the most failures and touched 1. The order has flipped.", apply: { op: "summarize", by: ["IPAddress"], as: "accounts" } },
              { id: "b", text: "| summarize sources = count() by AccountName", why: "This counts sources per account, and every account here has one. That axis is worth running on its own, but it doesn't answer this question.", apply: { op: "summarize", by: ["AccountName"], as: "sources" } },
              { id: "c", text: "| summarize n = count() by attempts", why: "A histogram of attempt counts. Interesting shape, but it no longer says which source did what.", apply: { op: "summarize", by: ["attempts"], as: "n" } },
            ],
          },
          {
            id: "bar", ask: "Line 6: a front desk at shift change touches up to 3 accounts, and that's normal. Set the bar.",
            choices: [
              { id: "a", text: "| where accounts >= 2", why: "Two front desks came through with the source you want. A bar at the normal level pages somebody every shift change.", apply: { op: "where", col: "accounts", test: "in", value: atLeast(2) } },
              { id: "b", text: "| where accounts >= 6", right: true, why: "One row: 10.60.12.40 and its 9 accounts. The bar sits above the busiest honest source and below the attack.", apply: { op: "where", col: "accounts", test: "in", value: atLeast(6) } },
              { id: "c", text: "| where accounts >= 50", why: "No results. A bar set for a big company's noise misses a small, careful attacker. Breadth is relative to your own baseline.", apply: { op: "where", col: "accounts", test: "in", value: atLeast(50) } },
            ],
          },
        ],
        expect: 1,
        lesson: "Group by source, then count accounts, and the deep attack and the wide attack swap places. Look at what the bar dropped: six addresses with one account each, all at the Staff Portal. Per-source breadth can't see a run that spreads across sources, so ask the same question on another axis. Tuesday's seven accounts stayed out only because the window kept them out.",
      },
    ],
    // ── Matching: the shapes, from numbers ──
    "cred-m1": [
      {
        kind: "sort",
        title: "Name the Shape From the Numbers",
        prompt: "Your hunt gives numbers, not names. Findings from across the group's last year, with the labels cut off. Read accounts, attempts, sources and successes, and name the shape. Two cards still carry a rule title: ignore what it says.",
        primer: {
          title: "Four numbers name a shape",
          points: [
            "**Accounts touched:** one, or many?",
            "**Attempts on each account:** many means guessing at one target. A handful means staying thin.",
            "**Sources:** one steady source, or a crowd of addresses taking one turn each?",
            "**Successes for the effort:** guesses rarely hit. A high success rate for very little effort means the passwords were already known.",
          ],
          example: {
            label: "Reading one, in a different setting: a loyalty site",
            lines: [
              "9,000 accounts, 1 attempt each, 6,000 addresses, 540 successes.",
              "Wide, one try each, a crowd of sources, and 6% success with no guessing. That number doesn't come from guessing, so the passwords were already known.",
            ],
          },
        },
        buckets: [
          { id: "brute", label: "Brute force" },
          { id: "spray", label: "Password spray" },
          { id: "stuff", label: "Credential stuffing" },
        ],
        items: [
          { id: "n1", text: "1 account · 312 attempts · 1 source · 0 successes", bucket: "brute", why: "All the effort lands on one target. Depth, no breadth." },
          { id: "n2", text: "86 accounts · 2 attempts each · 1 source · 0 successes", bucket: "spray", why: "Wide and thin from one place. Zero successes doesn't change the shape." },
          { id: "n3", text: "410 accounts · 1 attempt each · 290 sources · 31 successes", bucket: "stuff", why: "A crowd of sources, one try each, and 7.6% success. That rate means real passwords, not guesses." },
          { id: "n4", text: "1 account · 900 attempts · 1 source · rule title: Password Spray Detected", bucket: "brute", why: "The title is what the rule's author hoped to catch. One account is not a spray, whatever the title says." },
          { id: "n5", text: "64 accounts · 1 attempt each · 1 source · rule title: Brute Force Detected", bucket: "spray", why: "Wide from one source. The numbers beat the title." },
          { id: "n6", text: "27 accounts · 3 attempts each · 3 addresses in one /24 · 1 success", bucket: "spray", why: "Three tries an account is guessing: a stolen pair needs one. Three neighbouring addresses are one actor rotating, not a crowd." },
          { id: "n7", text: "2,000 accounts · 1 attempt each · 1,800 sources · 90 successes", bucket: "stuff", why: "Nearly one source per attempt, and a hit rate no guess produces." },
          { id: "n8", text: "1 account · 40 attempts a day for nine days · 1 source · 0 successes", bucket: "brute", why: "Slow, but still one target. Pace changes how you detect it, not what it is." },
          { id: "n9", text: "120 accounts · 1 attempt each · 2 sources · 0 successes", bucket: "spray", why: "One attempt each could be stuffing, but two sources is not a crowd, and nothing succeeded. Read the source count before you decide." },
        ],
      },
    ],
    // ── Log analysis 1: deep, and why nothing locked ──
    "cred-la1": [
      {
        kind: "worksheet",
        title: "Why Didn't It Lock?",
        prompt: "conf.salonazul, the shared conference-room login, took 14 bad passwords overnight and never locked. Ewan pulled five accounts from the same week, with the policy each one sits under. Domain default: lock at 6, and the count resets after 30 minutes.",
        primer: {
          title: "How lockout really works",
          points: [
            "Active Directory counts bad passwords per account. At the **lockout threshold** the account locks.",
            "The count clears after the **reset window**, so spaced-out guesses may never add up.",
            "A **fine-grained password policy** can give one group a different threshold. A threshold of **0 means never lock**.",
          ],
          example: {
            label: "Same idea, other data: a room safe",
            lines: [
              "The safe locks after 3 wrong codes, and its counter clears after an hour.",
              "2 wrong codes, a 61-minute wait, 2 more: all day, and it never locks. The safe is working as built, and it still isn't protecting anything.",
            ],
          },
        },
        caption: "Active Directory · bad password counts, this week",
        columns: ["Account", "Threshold", "Bad passwords", "Last Status seen"],
        rows: [
          ["m.lopes", "6", "6 in 9 min", "0xC0000234"],
          ["h.duarte", "6", "3 in 12 min", "0xC000006D"],
          ["conf.salonazul", "0", "14 in 26 min", "0xC000006D"],
          ["pms.feed", "50", "22 in 40 min", "0xC000006D"],
          ["revman.api", "6", "5 every 35 min, 40 today", "0xC000006D"],
        ],
        questions: [
          { id: "zero", q: "conf.salonazul took 14 bad passwords and never locked. What number in its row explains that?", hint: "Which column would normally have stopped it?", answer: ["0", "zero"], why: "A threshold of 0 means this account can never lock. Somebody chose that, probably so a meeting would never be stuck. Find out who, and whether it's still needed." },
          { id: "reset", q: "revman.api took 40 bad passwords today at threshold 6. What is the highest its counter ever reached?", hint: "The count resets after 30 minutes. How long is the pause between bursts?", answer: ["5", "five"], why: "Five, then a 35-minute pause, and the 30-minute reset clears it. A patient script can repeat this forever, so count per day as well as per burst." },
          { id: "open", q: "How many of these five accounts can still be guessed right now?", hint: "Which rows show a lock code?", answer: ["4", "four"], why: "Only m.lopes is locked. A quiet lockout column is not good news: nothing has stopped the other four, and the next guess could be the right one." },
          { id: "domain", q: "m.lopes locked at 6 in this same domain. Is lockout switched off for the whole domain? (yes/no)", hint: "Read each account against its own threshold.", answer: ["no", "n"], why: "One account's missing lock code tells you about that account. Read its own policy before you say anything about the domain." },
        ],
      },
      {
        kind: "sequence",
        title: "First Moves on a Deep Burst",
        prompt: "conf.salonazul, 14 failures from 10.60.31.77, a wall port on the Lisbon conference floor. Nothing locked. Put Ewan's first moves in order, the way you'd work it with the source still live.",
        items: [
          { id: "ask", text: "Ring the conference desk: did anyone set up a room PC with an old password last night?", note: "A dull explanation is possible, so check it, but only once the live risk is handled." },
          { id: "note", text: "Write down what you found, and close or escalate on that", note: "The ticket records what you checked, not just what you concluded." },
          { id: "cut", text: "Shut the wall port so the guessing stops", note: "The port is still live and can start again. Close it first, while nothing else is at stake." },
          { id: "gap", text: "Find out why this login can never lock, and whether it must stay that way", note: "The same gap is open tomorrow if nobody asks." },
          { id: "proof", text: "Search the whole night for any success from that source, not just the record in front of you", note: "The record on screen is one row of fourteen. The answer sits in the rows you haven't read." },
        ],
        order: ["cut", "proof", "ask", "gap", "note"],
        doneNote: "Stop it, prove whether it worked, rule out the dull explanation, close the gap, write it up.",
      },
    ],
    // ── Log analysis 2: wide, and proving a success ──
    "cred-la2": [
      {
        kind: "worksheet",
        title: "Is the Cap an Accident?",
        prompt: "From the group's incident review: three spray findings at hotels the group runs, and one busy shift start for comparison. Domain policy moved from 10 to 6 in the spring. Read the top attempt count against the policy.",
        primer: {
          title: "Read the cap, not the total",
          points: [
            "The **cap** is the highest attempt count on any single account.",
            "Spray tools read the lockout policy before the first guess. From any domain foothold, `net accounts /domain` prints it.",
            "An honest crowd has an untidy top end. A tool sits on a line.",
          ],
          example: {
            label: "Same idea, other data: a card reader",
            lines: [
              "A till blocks a card after 3 failed PINs. Forty cards each show exactly 2 failed PINs, none show 3.",
              "Real customers forget in all sorts of amounts. Forty identical stops one short of the limit is a method.",
            ],
          },
        },
        caption: "Incident review · spray findings and one normal morning",
        columns: ["Finding", "Policy", "Accounts", "Cap", "Lockouts", "Successes"],
        rows: [
          ["March, Porto", "10", "120", "9", "0", "0"],
          ["June, Faro", "6", "88", "5", "0", "1"],
          ["August, Lisbon", "6", "140", "5", "0", "2"],
          ["Monday shift start", "6", "14", "6", "1", "14"],
        ],
        questions: [
          { id: "gap", q: "In the three spray findings, how far below the policy does the cap sit?", hint: "Policy minus cap, row by row.", answer: ["1", "one"], why: "Always one. Across different hotels and different months, that's not chance. It's a setting in a tool." },
          { id: "follow", q: "Policy dropped from 10 to 6 between March and June. Did the cap drop with it? (yes/no)", hint: "Compare the March row with June.", answer: ["yes", "y"], why: "The cap follows the policy, because the tool reads the policy first. A shift start has no such line: Monday reached 6 and somebody locked themselves out." },
          { id: "zero", q: "Add up the successes in the three sprays, all of which show 0 lockouts.", hint: "0 + 1 + 2.", answer: ["3", "three"], why: "Zero lockouts, three accounts lost. The lockout column can't answer the question you care about, so success is the number you go and find." },
        ],
      },
      {
        kind: "hunt",
        title: "Prove a Success Followed",
        prompt: "Your query named 10.60.12.40, the shared PC in the Lisbon training room, and you saved its targets. Lockouts: none, which tells you nothing either way. Join the targets to the sign-ins and find out whether a guess landed, and only a success that came after the failures counts.",
        primer: {
          title: "A join is only as good as its key",
          points: [
            "`join kind=inner T on A` pairs each row with every row in T that has the same A, and drops rows with no partner. Always state `kind`: the KQL default removes duplicate left-hand keys.",
            "When both sides have a column of the same name, the right-hand one comes back with a 1 on the end, such as `IPAddress1`.",
            "List two columns after `on` and a pair must match on both.",
            "Pick a key that means the same event on both sides. An account alone means that person, anywhere, at any time.",
          ],
          example: {
            label: "Same method, other data: badge swipes and the rota",
            lines: [
              "`Swipes | join kind=inner Rota on StaffId`: one swipe pairs with every shift that person ever worked.",
              "`Swipes | join kind=inner Rota on StaffId, Site`: only shifts at the site where the swipe happened.",
            ],
          },
        },
        language: "KQL",
        start: "SprayTargets",
        goal: "one row: the account a guess got into, with the proof",
        tables: [
          {
            name: "SprayTargets",
            note: "Saved with let from your last hunt, with FirstFailure = min(Timestamp) added: each account 10.60.12.40 failed against.",
            columns: ["IPAddress", "AccountName", "attempts", "FirstFailure"],
            rows: [
              ["10.60.12.40", "a.pinto", "2", "11-06 02:04"],
              ["10.60.12.40", "r.sousa", "2", "11-06 02:05"],
              ["10.60.12.40", "c.rocha", "2", "11-06 02:05"],
              ["10.60.12.40", "f.marques", "1", "11-06 02:06"],
              ["10.60.12.40", "n.tavares", "1", "11-06 02:06"],
              ["10.60.12.40", "o.reis", "1", "11-06 02:07"],
              ["10.60.12.40", "u.simoes", "1", "11-06 02:07"],
              ["10.60.12.40", "s.barros", "1", "11-06 02:08"],
              ["10.60.12.40", "h.teixeira", "1", "11-06 02:08"],
            ],
          },
          NIGHT,
        ],
        rungs: [
          {
            id: "key", ask: "Line 2: bring in the sign-ins. Choose the key that ties a sign-in to this attack.",
            choices: [
              { id: "a", text: "| join kind=inner IdentityLogonEvents on AccountName", why: "18 rows, including a.pinto at 06:52 from a front desk and f.marques at the night audit PC. Those are the same people in the places they work. An account alone is not this source.", apply: { op: "join", table: "IdentityLogonEvents", left: "AccountName", right: "AccountName" } },
              { id: "b", text: "| join kind=inner IdentityLogonEvents on IPAddress", why: "144 rows: all 9 targets paired with all 16 events from that PC. a.pinto is now matched to f.marques's sign-in. Every event on that address has to be paired with the account it belongs to.", apply: { op: "join", table: "IdentityLogonEvents", left: "IPAddress", right: "IPAddress" } },
              { id: "c", text: "| join kind=inner IdentityLogonEvents on AccountName, IPAddress", right: true, why: "16 rows: the same account, from the same address. Now every row is this account on this PC. Failures and successes are still mixed.", apply: { op: "join", table: "IdentityLogonEvents", left: "AccountName", right: "AccountName", also: "IPAddress" } },
            ],
          },
          {
            id: "won", ask: "Line 3: the question is whether anything got in.",
            choices: [
              { id: "a", text: '| where ActionType == "LogonFailed"', why: "12 rows: the failures you already knew about. You've just read your own input back.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonFailed" } },
              { id: "b", text: '| where ActionType == "LogonSuccess"', right: true, why: "4 rows, 3 accounts. Don't celebrate yet: staff train on this PC, so some of these may be nothing.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonSuccess" } },
              { id: "c", text: "| where attempts == 2", why: "That keeps the accounts hit twice, whatever the outcome. It says nothing about success, and a hit can take a single try.", apply: { op: "where", col: "attempts", test: "eq", value: "2" } },
            ],
          },
          {
            id: "after", ask: "Line 4: a success only counts if it followed the failures.",
            choices: [
              { id: "a", text: "| where Timestamp < FirstFailure", why: "Three rows, all Thursday: staff on a training course, hours before the first failure. That is the normal use of this PC, and proves nothing.", apply: { op: "where", col: "Timestamp", test: "has", value: "11-05" } },
              { id: "b", text: "| where Timestamp > FirstFailure", right: true, why: "One row. f.marques, failed at 02:06, signed in from the same PC at 03:27, with nobody on a course at that hour.", apply: { op: "where", col: "Timestamp", test: "has", value: "11-06" } },
              { id: "c", text: '| where AccountName == "f.marques"', why: "You chose by the name you can see, and you kept the 14:20 course session as well. A hunt has to work on names you haven't met.", apply: { op: "where", col: "AccountName", test: "eq", value: "f.marques" } },
            ],
          },
          {
            id: "show", ask: "Line 5: Ewan needs what proves it on the ticket. Keep those columns.",
            choices: [
              { id: "a", text: "| project TargetUserName, IpAddress, Timestamp", why: "Failed to resolve: those are the column names in a Windows event. Each table has its own names, so read the schema of the table you're in.", apply: { op: "project", cols: ["TargetUserName", "IpAddress", "Timestamp"] } },
              { id: "b", text: "| summarize count() by AccountName", why: "A count of 1 proves nothing. The times are the evidence, and this line threw them away.", apply: { op: "summarize", by: ["AccountName"] } },
              { id: "c", text: "| project AccountName, IPAddress, DeviceName, attempts, FirstFailure, Timestamp", right: true, why: "Who, from where, how many tries, first failure, and the success after it. Anyone can check that row in a minute.", apply: { op: "project", cols: ["AccountName", "IPAddress", "DeviceName", "attempts", "FirstFailure", "Timestamp"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "No lockouts meant nothing: one miss and one hit was enough for f.marques, a night auditor. Key the join on account and source so it means this attack on this account, then make the clock prove the order. One limit to remember: an inner join needs a failure to start from, and a guess that works first time leaves none. So also list every success from that source in the same hours. f.marques is now an incident, not a finding.",
      },
    ],
    // ── Verdict: bursts with an honest cause ──
    "cred-ac1": [
      {
        kind: "queue",
        title: "Name the Verdict",
        prompt: "Four tickets from the same rule, Repeated logon failures. It fired correctly on most of them. Open each one, read the fields and the context, and give the verdict that belongs on the ticket.",
        primer: {
          title: "Three verdicts, three different meanings",
          points: [
            "**True positive:** the rule saw what it was built for, and the activity is hostile or unexplained.",
            "**Benign true positive:** the rule saw exactly what it was built for, and a cause you can show makes it harmless. Cite that cause on the ticket.",
            "**False positive:** the rule fired on something that isn't what it claims to detect. The rule is what needs fixing.",
          ],
          example: {
            label: "The same three, on a smoke alarm",
            lines: [
              "Smoke from a kitchen fire: true positive.",
              "Smoke from a chef's flambe, on tonight's menu: benign true positive. The alarm was right, and nothing is wrong.",
              "An alarm that sounds on steam from a shower: false positive. There was never any smoke.",
            ],
          },
        },
        console: "SIEM · Repeated logon failures",
        actions: [
          { id: "tp", label: "True positive: escalate", tone: "escalate" },
          { id: "btp", label: "Benign true positive: close, cite the cause", tone: "close" },
          { id: "fp", label: "False positive: fix the rule", tone: "close" },
        ],
        alerts: [
          { id: "a1", time: "Tue 10:40", severity: "Medium", rule: "Repeated logon failures", entity: "scan.creds", fields: [{ k: "Failures", v: "140 in 20 min" }, { k: "Sources", v: "1 internal scanner node" }, { k: "SubStatus", v: "0xC000006A" }], context: "CHG-71204 covers a credentialed vulnerability scan on Tuesday from 10:30 to 12:00, from that node, with this account. IT confirms the password in the scan profile was mistyped.", answer: "btp", why: "Real failures, so the rule was right. The ticket names the account, the host and the window, and IT confirmed it. Close it and cite CHG-71204." },
          { id: "a2", time: "Wed 03:12", severity: "Medium", rule: "Repeated logon failures", entity: "b.araujo", fields: [{ k: "Failures", v: "60 in 30 min" }, { k: "EventID", v: "4634" }, { k: "Activity", v: "An account was logged off" }], context: "A parser update on Monday mapped this event into the failure field. Every one of these rows is a normal log-off.", answer: "fp", why: "Event ID 4634 is a log-off, so no logon failed at all. Nothing happened for a cause to explain: the rule's input is wrong, so fix the parser." },
          { id: "a3", time: "Fri 01:42", severity: "High", rule: "Repeated logon failures", entity: "conf.salonazul", fields: [{ k: "Failures", v: "14 in 26 min" }, { k: "Sources", v: "1, a conference floor wall port" }, { k: "SubStatus", v: "0xC000006A" }], context: "No ticket covers this. The conference desk had no event on the floor that night, and the port should be disabled after hours.", answer: "tp", why: "No record, no owner, and a source that shouldn't be live. Without a cause you can show, it stays an attack." },
          { id: "a4", time: "Thu 11:05", severity: "High", rule: "Repeated logon failures", entity: "210 accounts", fields: [{ k: "Attempts each", v: "1" }, { k: "Sources", v: "1, inside the IT range" }, { k: "SubStatus", v: "0xC000006A" }], context: "The CISO signed a red team engagement for this week. The scope letter names this host and today's window, and the lead tester confirms the run by phone.", answer: "btp", why: "It's a real spray and the rule was right to fire. Signed scope, named host, confirmed by a person: harmless, and the rule stays as it is." },
        ],
      },
      {
        kind: "intercept",
        title: "Explain It or Escalate It",
        prompt: "Saturday's queue, and every card looks like a burst. Is there a cause you can actually show, or not? Read the source and the paperwork, then explain it or escalate it before it lands.",
        primer: {
          title: "What an honest explanation needs",
          points: [
            "**Where from:** your own known hosts, or somewhere with no reason to care about this account?",
            "**When:** does it sit inside the window on the record, or just near it?",
            "**Who confirms:** a named person or a ticket. A plausible guess of yours is not evidence.",
            "Things that fail together usually share something: a change, a patch, a batch. Find the shared thing and you have your cause.",
          ],
          example: {
            label: "A worked call, on door locks",
            lines: [
              "Eight door locks on one floor alarm within a minute. All eight came from one battery batch, and maintenance has it logged: explained.",
              "Eight locks on one floor alarm, from mixed batches, with nothing logged and nobody on site who can account for it: escalate.",
            ],
          },
        },
        protect: "the day shift's morning",
        blockLabel: "Escalate",
        passLabel: "Explain and close",
        seconds: 12,
        items: [
          { id: "i1", text: "scan.creds: 90 failures from one scanner node", sub: "Inside CHG-71388's Saturday window, IT confirms", bad: false, why: "A known host, inside a window on the record, confirmed by a person. Close it and cite the ticket." },
          { id: "i2", text: "j.pereira: 38 failures from one external address at 03:00", sub: "No ticket, and the user is on leave", bad: true, why: "Nobody to confirm it and no reason for it. On leave makes it worse." },
          { id: "i3", text: "m.vaz: a failure every 5 minutes from one phone", sub: "Changed password Tuesday, confirms the mail app is still retrying", bad: false, why: "A device retrying an old password looks like a slow brute force. The owner confirmed it, so have them update the phone." },
          { id: "i4", text: "scan.creds: 90 failures from one scanner node", sub: "Three hours before CHG-71388's Saturday window opened", bad: true, why: "Same account, same host, but outside the window. A ticket covers only what it says it covers, so somebody has to explain this." },
          { id: "i5", text: "k.almeida: 3 failures, then a success, at the shift change", sub: "Own front desk PC, own usual hours, k.almeida confirms mistyping at handover", bad: false, why: "Usual place, usual hour, a success right after, and the owner confirms it. That's a typo." },
          { id: "i6", text: "adm.pms: failures from 6 PCs in 4 hotels in 3 minutes", sub: "No ticket, and none of those hotels' staff use this login", bad: true, why: "Internal hosts don't explain it by themselves. With no shared change behind it and no reason for those PCs to use this login, this looks like spread." },
          { id: "i7", text: "210 accounts, 1 attempt each, from one IT host", sub: "Signed scope letter names the host and window, lead tester confirms", bad: false, why: "A real spray, and an authorised one. Scope, host, window and a person." },
          { id: "i8", text: "90 unknown usernames from a guest Wi-Fi address", sub: "SubStatus 0xC0000064 on every one", bad: true, why: "Names that were never issued, from a network with no business reaching a DC. Nothing routine does that." },
          { id: "i9", text: "lockadmin: 12 failures from the door-lock server at Faro", sub: "Vendor upgrade ticket, one server, stopped when the upgrade ended", bad: false, why: "One known server, a ticket, and it stopped when the work stopped. That end point matters as much as the start." },
          { id: "i10", text: "l.reis: 2 failures, then a success, from a new address", sub: "User is asleep at home and hasn't heard of it", bad: true, why: "A small count means nothing here. A success the user denies is the worst card on the board." },
        ],
        lesson: "Size doesn't decide it. A burst of 140 can be routine and a run of 3 can be the incident. Ask where it came from, whether it sits inside a window on the record, and who confirms it. If you can show all three, close it and say why. If you can't, it stays open.",
      },
    ],
    // ── Ordering: what follows a success ──
    "cred-o1": [
      {
        kind: "sequence",
        title: "After the Hit",
        prompt: "The wall's other story. At 04:00 six addresses replayed leaked pairs at the Staff Portal, and s.ferreira's pair worked. That session turned into a payroll problem. Put the morning's events in the order they happened.",
        items: [
          { id: "pay", text: "s.ferreira's salary bank details are changed in the payroll app", note: "This is what the hit was for. Everything before it was the way in." },
          { id: "browse", text: "That session opens the staff directory and the payroll help pages for the first time ever", note: "Finding out what the account can reach. New behaviour for that person is the tell." },
          { id: "sweep", text: "Six addresses replay leaked pairs at the Staff Portal, and most fail", note: "The sweep. Every failure here is a cheap test of a stolen pair." },
          { id: "second", text: "s.ferreira signs in from 198.51.100.140, an address never seen for this account", note: "The attacker comes back through different infrastructure to work with the account. Hunting only the first address misses it." },
          { id: "hit", text: "s.ferreira's pair works from 203.0.113.63 at 04:11", note: "One success, from the same crowd as the failures." },
        ],
        order: ["sweep", "hit", "second", "browse", "pay"],
        doneNote: "Sweep, hit, come back, look around, reach for the prize. Each step shows up in a different place: the sign-in log, then new sources, then activity the user has never had. The earlier you break the run, the less you have to clean up, so a success is where the investigation starts, not where it ends.",
      },
    ],
    // ── The boss: writing the detection ──
    "cred-qf1": [
      {
        kind: "worksheet",
        title: "Pick the Window and the Bar",
        prompt: "Before a breadth rule ships, two numbers need a reason. Ewan replayed the slowest spray on file and Mariposa's busiest honest source through four window sizes. Pick the window and the bar from the data, not from a round number you like.",
        primer: {
          title: "Two choices every breadth rule makes",
          points: [
            "**The window** must be at least as long as the slowest attack you want to catch. Too short slices it into harmless-looking pieces.",
            "**Too long** a window lets honest sources build up breadth, until they look like attacks.",
            "**The bar** sits above your busiest honest source for that window, and below the attack.",
            "The numbers come from your own estate. Another company's bar means nothing here.",
          ],
          example: {
            label: "Same reasoning, other data: reception queries",
            lines: [
              "A reception system's normal peak is 4 lookups of different guests in 5 minutes, 30 in an hour.",
              "A rule on 5-minute windows can use a bar of 4. On hourly windows the same bar would fire all day.",
            ],
          },
        },
        caption: "Accounts touched by one source · by window · last 30 days · approved audit hosts excluded",
        columns: ["Window", "Slowest spray", "Busiest honest source"],
        rows: [
          ["10m", "3", "2"],
          ["3h", "37", "6"],
          ["24h", "37", "19"],
          ["7d", "37", "58"],
        ],
        questions: [
          { id: "window", q: "Which window is the shortest that shows the whole spray?", hint: "Find where the spray's number stops growing.", answer: ["3h", "3 h", "3 hours", "3hr"], why: "At 10 minutes the spray shows 3 accounts, barely above honest noise. By 3 hours all 37 accounts are in, and a longer window adds nothing to the spray and plenty to the noise." },
          { id: "bar", q: "At that window, what is the lowest N for `accounts > N` that never fires on the honest source?", hint: "Read the honest source's number in that row.", answer: ["6", "six"], why: "Above 6 and well under 37, so you have room. Real rules leave headroom over the honest peak, and in practice this one would go a little higher. The audit host touched 7 accounts in two minutes on Tuesday, so it needs an allowlist entry, or this rule pages on every approved audit." },
          { id: "long", q: "With that same bar on a 7d window, would the honest source fire? (yes/no)", hint: "Compare the bar with the 7d row.", answer: ["yes", "y"], why: "58 clears it easily. The bar only means something alongside its window, so whenever you change one, recheck the other." },
        ],
      },
    ],
  },
};
