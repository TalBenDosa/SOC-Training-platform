import type { RoomExperience } from "./types";

// "Operation Mapmaker" for the "discovery-and-enumeration" room.
// Script: docs/campaign/105-discovery-and-enumeration.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
// The room's own task order is kept.
//
// Selkirk Timber Cooperative (fictional), not the graded tasks' Meridian Capital or SecureLedger
// records. Mentor: Bahar Nkemelu, Detection Analyst.
// Signature: One Command Is Nothing, Ten Are a Map. Admins run whoami and net group too. A SPL
// hunt over native 4688 data stacks discovery commands per host, session and ten-minute window,
// and a tune sets how many different commands in how long means someone is looking around.
// Game mix: hunt + rush + tune.
// Lab data differs from the graded tasks: host labs read Remote Desktop Users and Backup
// Operators, and the 4798 anatomy has a PowerShell caller and a ticket, never the Administrators
// group, net.exe or a phishing click (la1, r2 checkpoint); foothold is a stolen VPN sign-in. The
// queue weighs lookups of named accounts and a 38-group LDAP loop, never net group "domain
// admins" run once against 200 times (q2, q4). Cloud labs use survey-sync-role on EC2 with 31
// calls across five services at 11:32, never a Lambda role with 47 calls at 02:06 (la2, f1), and
// T1619 is taught on ListObjectVersions and gcloud storage ls, with reads as storage.objects.get
// (q3, r5 checkpoint). The sequence climbs a cloud account in five steps, not a host in six (o1).
// The boss queue is scanners, CI and a misfired string match, never a nightly audit account on
// an audit server (ac1). Labs never ask the m1 pairs; a primer shows them in passing.
// disc-r3's reading and these labs agree: Get-ADUser and Get-ADGroupMember go over ADWS, TCP 9389.

const S = "C:\\Windows\\System32\\";
const CMD = `${S}cmd.exe`;
const WMI = `${S}wbem\\WmiPrvSE.exe`;
const INV = "C:\\Program Files\\AssetAgent\\agent.exe";
const HEALTH = "C:\\Program Files\\HealthAgent\\hagent.exe";
const D = "2026-11-05 ";

export const DISCOVERY_AND_ENUMERATION: RoomExperience = {
  roomId: "discovery-and-enumeration",
  codename: "Operation Mapmaker",
  theme: "mapmaker",
  handler: { name: "Bahar Nkemelu", role: "Detection Analyst, Selkirk Timber Cooperative" },
  briefing: [
    "Selkirk Timber Cooperative. 62 landowner members, one sawmill, one log yard, and a 20-year harvest licence bid due on Monday.",
    "At 09:12 on Thursday a log scaler's account typed whoami on a yard PC. Nothing fired, because nothing should fire on one whoami.",
    "Bahar Nkemelu thinks somebody is drawing a map of the co-op, one harmless question at a time.",
    "Learn what each question asks, stack the questions by session, set the line between an admin and an intruder, and finish before looking becomes taking.",
  ],
  mission: "Place each discovery command by what it asks, tell a local question from a domain one, read a cloud burst, order the climb from looking to taking, stack commands per session in SPL, tune the threshold, then make the final call on a real command.",
  estimate: "~60 min",
  look: { primary: "#c9b458", secondary: "#7fb6d6", warn: "#e8563f" },
  scene: "facilitymapmaker",
  layout: "facility",
  stations: [
    {
      id: "whoami",
      label: "The Whoami",
      topic: "Tactics and techniques · why Discovery is a pattern · host-level discovery, T1033 · Events 4798 and 4799",
      tagline: "One word on a yard PC",
      building: "office",
      taskIds: ["disc-r0", "disc-r1", "disc-r2", "disc-q1"],
    },
    {
      id: "domain",
      label: "The Domain Question",
      topic: "T1087.002 and T1069.002 · SAMR and LDAP · T1018 and T1046 · reading one event in its timeline",
      tagline: "From one machine to all of them",
      building: "control",
      taskIds: ["disc-r3", "disc-q2", "disc-r4", "disc-la1"],
    },
    {
      id: "cloud",
      label: "The Cloud Census",
      topic: "T1580, T1526, T1619 · GuardDuty finding names · reading CloudTrail records and bursts",
      tagline: "Same questions, different API",
      building: "vault",
      taskIds: ["disc-r5", "disc-q3", "disc-la2"],
    },
    {
      id: "map",
      label: "Ten Are a Map",
      topic: "T1135 to T1039 · the climb from looking to taking · baselining, breadth and velocity · benign true positives and allowlists",
      tagline: "Stack it before anything is taken",
      building: "lab",
      taskIds: ["disc-r6", "disc-o1", "disc-r7", "disc-q4"],
    },
    {
      id: "finishedmap",
      label: "The Finished Map",
      topic: "Weighing a real discovery command · every technique in the room · the value you pivot on",
      tagline: "The rule fired. Now what?",
      building: "ticket",
      taskIds: ["disc-ac1", "disc-m1", "disc-f1"],
      boss: true,
    },
  ],
  personas: {
    "disc-q1": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "Everyone types the same thing first. What does ATT&CK call it?" },
    "disc-q2": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "Two cases on my desk. Tell me how you'd weigh them." },
    "disc-la1": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "A friend at a finance firm sent me this record. Read it as if it were ours." },
    "disc-q3": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "A finding like this one, in somebody else's account. What did it see?" },
    "disc-la2": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "Another one from outside the co-op. Start with the record, then the summary." },
    "disc-o1": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "Put the steps back in the order they happened." },
    "disc-q4": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "Two sources, one hour. What does each one get from you?" },
    "disc-ac1": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "This one came in from a partner's SOC. Read it properly before you touch it." },
    "disc-m1": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "Last job on the chart: label it." },
    "disc-f1": { name: "Bahar Nkemelu", role: "Detection Analyst", line: "One value to carry out of this room. Go back to the record if you need to." },
  },
  briefings: {
    // ── Reading 0: tactic and technique ──
    "disc-r0": [
      {
        kind: "sort",
        title: "Name the Goal Before the Tool",
        prompt: "Thursday, 09:40, Selkirk's detection desk. Bahar has a list of things seen on the network this year, several from tools nobody could name. You don't need to know a tool to place it. Ask what the person running it wanted, and file each one under that goal.",
        buckets: [
          { id: "disc", label: "Discovery: what is here?" },
          { id: "cred", label: "Credential Access: whose secrets can I get?" },
          { id: "pers", label: "Persistence: how do I stay?" },
          { id: "coll", label: "Collection: what can I gather?" },
        ],
        items: [
          { id: "i1", text: "A renamed binary prints every machine on the subnet that answered", bucket: "disc", why: "The tool is unknown and the question isn't: what can I reach from here? The goal places it, and the exact technique can be looked up after." },
          { id: "i2", text: "A small .exe nobody recognises lists the current account's groups", bucket: "disc", why: "It changes nothing and takes nothing. It only asks where this account stands." },
          { id: "i3", text: "A script reads the cloud account's list of virtual machines", bucket: "disc", why: "The same question, asked through an API. Discovery isn't tied to Windows." },
          { id: "i4", text: "reg save HKLM\\SAM sam.hiv", bucket: "cred", why: "This copies the local account database so its password hashes can be cracked offline. The goal is someone's secret." },
          { id: "i5", text: "A process opens the memory of lsass.exe", bucket: "cred", why: "LSASS holds credential material in memory. Nobody reads it out of curiosity about the network." },
          { id: "i6", text: "schtasks /create /tn Updater /sc onlogon /tr C:\\Users\\Public\\u.exe", bucket: "pers", why: "A task that runs at every logon is a way back in after a restart." },
          { id: "i7", text: "A new Run key value points at a file in AppData", bucket: "pers", why: "Same goal, different method: one tactic groups many techniques." },
          { id: "i8", text: "robocopy \\\\SLK-FILE02\\Survey C:\\ProgramData\\s /E", bucket: "coll", why: "This one isn't asking what exists any more. It's gathering the files." },
          { id: "i9", text: "7z a stock.7z C:\\ProgramData\\s\\*", bucket: "coll", why: "Packing up what was gathered, ready to leave. Discovery is long over by this point." },
        ],
        primer: {
          title: "Tactic and technique",
          points: [
            "**ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is MITRE's public catalogue of how real attackers operate, built from observed intrusions.",
            "A **tactic** is the goal: why the attacker is doing this now. Tactic IDs start with TA.",
            "A **technique** is the method: how they reach that goal. Technique IDs start with T, and a sub-technique adds a dot, as in T1087.002.",
            "**Discovery** is tactic **TA0007**: the adversary is trying to figure out your environment. Credential Access is TA0006, Persistence TA0003, Collection TA0009.",
            "Every technique carries the tactic it serves, so a brand-new tool can be placed by what it's trying to do.",
          ],
          example: {
            label: "A worked placement: a tool with no name",
            lines: [
              "Seen: `svcupd.exe` sets a service to start at boot.",
              "What is it after? It isn't asking anything. It's changing the host so it survives a restart.",
              "Goal: Persistence, TA0003. The technique ID can wait.",
            ],
          },
        },
      },
    ],
    // ── Reading 1: why Discovery is a pattern ──
    "disc-r1": [
      {
        kind: "worksheet",
        title: "One Line Proves Nothing",
        prompt: "This is the hour Bahar is worried about, Thursday 08:30 to 09:30, every discovery-looking process the Security log recorded. Nobody has judged these rows yet. Work out what a row can tell you, and what only the table can.",
        caption: "Security log · Event ID 4688, process creation · 2026-11-05 08:30 to 09:30",
        columns: ["Time", "Host", "Account", "Command"],
        rows: [
          ["08:41:17", "SLK-IT-02", "adm-r.sato", "whoami"],
          ["08:44:52", "SLK-PLAN-04", "l.ferreira", "ipconfig /all"],
          ["08:52:03", "SLK-IT-02", "adm-r.sato", "net user l.ferreira /domain"],
          ["09:12:04", "SLK-YARD-07", "n.halvorsen", "whoami"],
          ["09:12:39", "SLK-YARD-07", "n.halvorsen", "ipconfig /all"],
          ["09:13:11", "SLK-YARD-07", "n.halvorsen", "net user"],
          ["09:13:58", "SLK-YARD-07", "n.halvorsen", "query user"],
          ["09:14:30", "SLK-YARD-07", "n.halvorsen", "net localgroup \"Remote Desktop Users\""],
          ["09:15:06", "SLK-YARD-07", "n.halvorsen", "net config workstation"],
          ["09:17:22", "SLK-YARD-07", "n.halvorsen", "nltest /dclist:selkirktimber.example"],
          ["09:21:44", "SLK-PLAN-04", "l.ferreira", "whoami"],
        ],
        questions: [
          { id: "tools", q: "How many of these rows ran a program that doesn't ship with Windows?", hint: "Read the first word of each command. whoami, ipconfig, net, query, nltest.", answer: ["0", "zero", "none"], why: "Zero. There's no malware file here to catch, and every row was logged. The trouble isn't missing data: the log is full of these." },
          { id: "rule", q: "A rule that alerts on the word whoami would fire how many times on this table?", hint: "Count the rows whose command is whoami.", answer: ["3", "three"], why: "Three times, and two of those are colleagues at work. The row looks the same whoever typed it." },
          { id: "shape", q: "Which host ran the most different commands inside ten minutes?", hint: "Group the rows by host, then look at the times.", answer: ["SLK-YARD-07", "YARD-07"], why: "SLK-YARD-07: seven different commands in under six minutes, from a log scaler's account. That isn't proof either. But it's a shape, and you can't see a shape in one row." },
        ],
        primer: {
          title: "Discovery in the logs",
          points: [
            "**Discovery** usually sits right after Initial Access and Execution. Someone who just landed doesn't yet know if this is a laptop or a server, or what the stolen account is worth.",
            "Later attacks depend on it: an attacker has to learn which account or which bucket matters before going after it.",
            "Host, domain and cloud all get the same treatment in this room, from one machine up to a whole environment.",
            "Read each table twice: once a row at a time, then as a group by who and where.",
          ],
          example: {
            label: "A worked read: tasklist",
            lines: [
              "`tasklist` ran on a finance PC at 11:02.",
              "As a row, it says a built-in command ran. That's all it can say.",
              "The next questions are about the rows around it: who, what else, and how close together.",
            ],
          },
        },
      },
    ],
    // ── Reading 2: host-level discovery ──
    "disc-r2": [
      {
        kind: "sort",
        title: "Three Questions on One Machine",
        prompt: "These commands all ran on hosts at Selkirk this month. They feel alike, but ATT&CK gives them separate IDs and Bahar writes the exact one in every ticket. File each command under the question it actually asks.",
        buckets: [
          { id: "t1033", label: "T1033 System Owner/User Discovery: who is using this machine?" },
          { id: "t1087", label: "T1087.001 Local Account: which accounts exist here?" },
          { id: "t1069", label: "T1069.001 Local Groups: who is in which group here?" },
        ],
        items: [
          { id: "i1", text: "query user", bucket: "t1033", why: "Who else is logged on right now. T1033 is about the people on this box." },
          { id: "i2", text: "net config workstation", bucket: "t1033", why: "Basic host identity, with the logged-on user name. The room files it under T1033." },
          { id: "i3", text: "quser /server:SLK-PLAN-04", bucket: "t1033", why: "The same question as query user, aimed at a named machine." },
          { id: "i4", text: "net user", bucket: "t1087", why: "With no target, net user lists every local account on the machine." },
          { id: "i5", text: "Get-LocalUser", bucket: "t1087", why: "The PowerShell way of asking the same thing. Tool changes, technique doesn't." },
          { id: "i6", text: "wmic useraccount where localaccount=true get name", bucket: "t1087", why: "A third route to the same list: local accounts by name." },
          { id: "i7", text: "net localgroup \"Remote Desktop Users\"", bucket: "t1069", why: "One local group's members, and Windows logs it as Event 4799." },
          { id: "i8", text: "Get-LocalGroupMember -Group \"Backup Operators\"", bucket: "t1069", why: "Membership of a local group again, so the same ID whichever shell asked." },
          { id: "i9", text: "net localgroup", bucket: "t1069", why: "With no group named, it lists the groups that exist on this machine." },
        ],
        primer: {
          title: "One idea, three IDs",
          points: [
            "**T1033** is the umbrella an analyst reaches for first: `whoami`, `query user`, `net config workstation`.",
            "**T1087.001** is listing local accounts, the kind stored in this machine's SAM database.",
            "**T1069.001** is reading local groups.",
            "`net user` with no target lists accounts. `net user <name>` reads one account's local groups, which logs Event 4798.",
          ],
          example: {
            label: "A worked placement: the same three on Linux",
            lines: [
              "`who` shows who is logged on: T1033.",
              "`cat /etc/passwd` shows which accounts exist: T1087.001.",
              "`getent group sudo` shows who is in one group: T1069.001.",
            ],
          },
        },
      },
      {
        kind: "anatomy",
        title: "Anatomy of a 4798",
        prompt: "Some discovery leaves a Security event of its own. This one is from SLK-PLAN-04, while helpdesk was rebuilding a planner's laptop. Read it field by field before you meet its sibling.",
        source: "Windows Security · Event ID 4798 · SLK-PLAN-04",
        fields: [
          { key: "EventID", value: "4798", label: "What", note: "A user's local group membership was enumerated. Its sibling 4799 has the same shape for a group: a security-enabled local group's members were read." },
          { key: "Computer", value: "SLK-PLAN-04.selkirktimber.example", label: "Where" },
          { key: "SubjectUserName", value: "adm-r.sato", label: "Who asked" },
          { key: "SubjectDomainName", value: "SELKIRK" },
          { key: "SubjectLogonId", value: "0x1f4a92", note: "The logon session the request ran in." },
          { key: "TargetUserName", value: "l.ferreira", label: "About whom", note: "The account whose groups were read. On a 4799 the Target fields name the group instead." },
          { key: "TargetSid", value: "S-1-5-21-3390217754-1847702256-2840165532-1408" },
          { key: "CallerProcessId", value: "0x2a1c" },
          { key: "CallerProcessName", value: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", label: "With what", note: "The full path of the executable that made the call." },
        ],
        summary: "4798 asks which groups this user is in. 4799 asks who is in this group. Windows logs both constantly, because ordinary admin tools trigger them, so neither event is a finding by itself. Three things are worth reading on any of them: who asked, about what, and with which program. This one has a ticket: INC-4471, laptop rebuild.",
      },
      {
        kind: "sort",
        title: "Normal Hum or Second Look?",
        prompt: "Eight 4798 and 4799 events from Selkirk's last day. Windows logged all of them. Decide which ones belong to the building's normal hum and which deserve a second look. Read the program first, then the place it ran.",
        buckets: [
          { id: "hum", label: "Normal for this host" },
          { id: "look", label: "Second look" },
        ],
        items: [
          { id: "i1", text: "4799 · Hyper-V Administrators · mmc.exe · adm-r.sato on SLK-IT-02", bucket: "hum", why: "An admin console, an admin account, the helpdesk workstation. All three fit." },
          { id: "i2", text: "4799 · Backup Operators · VSSVC.exe · SLK-FILE02$ on SLK-FILE02", bucket: "hum", why: "Volume Shadow Copy reads this group during a backup. The account is the machine itself." },
          { id: "i3", text: "4798 · n.halvorsen · LogonUI.exe · SLK-YARD-07$ on SLK-YARD-07", bucket: "hum", why: "The sign-in screen reads an account's groups at logon. It's the yard PC, and it's still just a logon." },
          { id: "i4", text: "4799 · Remote Management Users · powershell.exe · adm-r.sato on SLK-IT-02", bucket: "hum", why: "A command-line tool, but in an admin's hands on an admin's machine. The program is a signal, not a verdict, so read it with the place." },
          { id: "i5", text: "4799 · Backup Operators · powershell.exe · n.halvorsen on SLK-MILL-03", bucket: "look", why: "A command-line tool, on a mill office PC, from a log scaler's account. Nothing about the place explains the program." },
          { id: "i6", text: "4799 · Power Users · rundll32.exe · l.ferreira on SLK-PLAN-04", bucket: "look", why: "rundll32 runs code from a DLL. No admin task reads a local group that way." },
          { id: "i7", text: "4798 · adm-r.sato · wmiprvse.exe · g.sandoval on SLK-KIOSK-01", bucket: "look", why: "wmiprvse.exe hosts WMI, so a WMI client made this request, possibly from another machine. Check the session's logon type." },
          { id: "i8", text: "4799 · Remote Desktop Users · mmc.exe · l.ferreira on SLK-PLAN-04", bucket: "look", why: "The program looks right, the rest doesn't: a planner has no admin console work on their laptop. Read all of it." },
        ],
        primer: {
          title: "Who usually does this",
          points: [
            "`mmc.exe` is the Microsoft Management Console, the shell that admin tools such as Local Users and Groups run in. `dsa.msc` is Active Directory Users and Computers.",
            "Windows itself reads groups too: `VSSVC.exe` during backups, `LogonUI.exe` at the sign-in screen.",
            "`net.exe`, `cmd.exe` and `powershell.exe` are command-line tools, a different way of asking.",
            "The same program means something else in a different place. An admin's workstation and a clerk's PC aren't the same baseline.",
          ],
          example: {
            label: "A worked read: a server at a law firm",
            lines: [
              "4799 on `LEX-SRV3`, group Event Log Readers, program `wsmprovhost.exe`.",
              "That process hosts remote PowerShell, so the request came from another machine.",
              "Next question: which machine, and did someone there mean to?",
            ],
          },
        },
      },
    ],
    // ── Reading 3: domain-wide discovery ──
    "disc-r3": [
      {
        kind: "rush",
        title: "Who Answers?",
        prompt: "The telemetry for a discovery command lives wherever the question was answered, so Bahar needs that before anything else. For each command, call it fast: does this machine answer, or a Domain Controller?",
        trueLabel: "This machine",
        falseLabel: "A Domain Controller",
        target: 10,
        cards: [
          { id: "c1", text: "net localgroup \"Remote Desktop Users\"", answer: true, why: "No /domain flag, so the local SAM database answers." },
          { id: "c2", text: "net group \"Yard Supervisors\" /domain", answer: false, why: "/domain sends it to a DC over SAMR, on the samr named pipe." },
          { id: "c3", text: "query user", answer: true, why: "Logged-on users are this host's own state." },
          { id: "c4", text: "Get-ADGroupMember \"Yard Supervisors\"", answer: false, why: "PowerShell's AD module goes over ADWS, TCP 9389, which queries the directory on the DC." },
          { id: "c5", text: "net user", answer: true, why: "No flag, no target: every local account." },
          { id: "c6", text: "dsquery group -name \"*admin*\"", answer: false, why: "dsquery is an LDAP client, so a DC answers." },
          { id: "c7", text: "Get-LocalGroupMember \"Backup Operators\"", answer: true, why: "Local group, local answer." },
          { id: "c8", text: "Get-ADUser -Filter *", answer: false, why: "Over ADWS, TCP 9389, which queries the directory on the DC, for every domain account." },
          { id: "c9", text: "AdFind -f objectcategory=group", answer: false, why: "AdFind speaks LDAP. It's offensive tooling and an admin's friend alike." },
          { id: "c10", text: "net config workstation", answer: true, why: "Basic identity of this machine." },
          { id: "c11", text: "net user l.ferreira /domain", answer: false, why: "One name, still /domain, so SAMR to a DC." },
          { id: "c12", text: "SharpHound collecting group memberships", answer: false, why: "It does that over LDAP, against a DC." },
          { id: "c13", text: "whoami /priv", answer: true, why: "It reads the current token. Nothing leaves the host." },
          { id: "c14", text: "net localgroup", answer: true, why: "The list of this machine's own groups." },
        ],
        lesson: "A local question reads this machine's SAM, and any 4799 stays on this machine. /domain goes to a DC over SAMR, an RPC interface on the samr pipe over SMB file sharing, port 445, and shows as Event 4661 when SAM auditing is on. Get-ADUser and Get-ADGroupMember go over ADWS, TCP 9389, which queries the directory on the DC, so monitoring port 389 misses them. dsquery, AdFind and SharpHound use LDAP, seen as query volume, or Event 1644 with expensive-search logging on.",
        primer: {
          title: "Two places to ask",
          points: [
            "Local commands read this machine's **SAM**, the Security Account Manager database.",
            "`net` with `/domain` asks a **Domain Controller** (DC) over **SAMR**, the Security Account Manager Remote protocol. Not over LDAP.",
            "PowerShell's `Get-ADUser`, `Get-ADGroup` and `Get-ADGroupMember` go over **ADWS**, Active Directory Web Services, TCP 9389, which queries the directory on the DC. `dsquery`, AdFind and SharpHound use **LDAP**, the Lightweight Directory Access Protocol.",
            "**T1087.002** is listing domain accounts: `Get-ADUser`, `dsquery`, BloodHound. **T1069.002** targets privileged groups: `Get-ADGroup`, `net group`.",
            "Microsoft Defender for Identity has a SAMR reconnaissance detection and LDAP reconnaissance detections.",
          ],
          example: {
            label: "A worked route: one group name, three roads",
            lines: [
              "`net localgroup \"Print Team\"`: no `/domain`, so the local SAM answers.",
              "`net group \"Print Team\" /domain`: a DC answers over SAMR.",
              "`Get-ADGroup \"Print Team\"`: over ADWS, TCP 9389, which queries the directory on the DC.",
            ],
          },
        },
      },
      {
        kind: "queue",
        title: "Four Domain Queries, One Queue",
        prompt: "Selkirk's SIEM, the central log and alert console, raised four domain-enumeration alerts today. Every command in them is a legitimate one. Read who asked, from what kind of machine, and how much they touched, then decide what each alert deserves.",
        console: "SIEM · Domain enumeration · Today",
        actions: [
          { id: "close", label: "Close: routine", tone: "close" },
          { id: "lead", label: "Keep open: follow it up", tone: "contain" },
          { id: "esc", label: "Escalate now", tone: "escalate" },
        ],
        alerts: [
          { id: "a1", time: "08:52", severity: "Low", rule: "Domain account query by net.exe", entity: "SLK-IT-02",
            fields: [{ k: "account", v: "adm-r.sato" }, { k: "command", v: "net user l.ferreira /domain" }, { k: "objects read", v: "1" }, { k: "host role", v: "Helpdesk workstation" }, { k: "ticket", v: "INC-4471 laptop rebuild" }],
            context: "An admin account, on an admin's workstation, looking up the person on the ticket.", answer: "close", why: "The command is the same one an intruder would use. What differs is the machine it came from: this source is expected, and the ticket says why." },
          { id: "a2", time: "10:47", severity: "High", rule: "LDAP query volume: group lookups", entity: "SLK-MILL-03",
            fields: [{ k: "account", v: "n.halvorsen" }, { k: "source", v: "10.40.12.33" }, { k: "objects read", v: "38 groups" }, { k: "span", v: "4 minutes" }, { k: "host role", v: "Mill office PC" }],
            context: "No ticket. A log scaler's account on a PC in the mill office, working through every group in the domain.", answer: "esc", why: "Breadth is what raises confidence: one source, group after group, in a tight window, from a machine with no admin job. Nobody does that by hand out of curiosity." },
          { id: "a3", time: "11:26", severity: "Medium", rule: "Group query from non-admin endpoint", entity: "SLK-PLAN-04",
            fields: [{ k: "account", v: "l.ferreira" }, { k: "command", v: "Get-ADGroupMember \"Harvest Planners\"" }, { k: "objects read", v: "1 group, once" }, { k: "host role", v: "Planner laptop" }, { k: "prior domain queries", v: "None in 90 days" }],
            context: "A planner reading the group for their own team. Nothing around it in the timeline so far.", answer: "lead", why: "An unexpected source makes it worth keeping. One query on its own can't carry a conclusion either way, so note it and look at what comes next from this host." },
          { id: "a4", time: "13:05", severity: "Medium", rule: "Domain account query by Get-ADUser", entity: "SLK-IT-02",
            fields: [{ k: "account", v: "adm-r.sato" }, { k: "objects read", v: "62 accounts" }, { k: "span", v: "1 minute" }, { k: "host role", v: "Helpdesk workstation" }, { k: "ticket", v: "CHG-2290 leavers check" }],
            context: "A planned check of leavers against the HR list, with a change record behind it.", answer: "close", why: "High volume, and still routine: an admin machine, an admin account and a change record. Volume means something once you know who it's from." },
        ],
        primer: {
          title: "Where a query comes from",
          points: [
            "MITRE's guidance for T1087.002 starts with the machine a query came from: one that is neither a DC nor an admin's is what it asks you to watch.",
            "The trigger is the combination of command and unexpected source, not the command alone.",
            "**Breadth** means many accounts or groups touched in a tight window. It raises confidence fast.",
            "Know each host's role before you read the command line. An asset list settles more than a regex.",
          ],
          example: {
            label: "A worked read: start from the host",
            lines: [
              "`Get-ADComputer -Filter *` ran on `HQ-JUMP1`.",
              "The asset list says: admin jump host.",
              "So the first question, is this source expected, has an answer before you've read a single flag.",
            ],
          },
        },
      },
    ],
    // ── Reading 4: T1018 and T1046 ──
    "disc-r4": [
      {
        kind: "sort",
        title: "Exists, or What Runs There?",
        prompt: "Selkirk's firewall team sent over commands from a past test of the network. One family finds machines. The other asks what's running on a machine already found. Bahar wants the right ID on each.",
        buckets: [
          { id: "t1018", label: "T1018 Remote System Discovery: what machines exist?" },
          { id: "t1046", label: "T1046 Network Service Discovery: what runs on them?" },
        ],
        items: [
          { id: "i1", text: "for /L %i in (1,1,254) do ping -n 1 10.40.12.%i", bucket: "t1018", why: "A ping sweep: which addresses answer. It says nothing about services." },
          { id: "i2", text: "net view", bucket: "t1018", why: "With no target it lists the machines it can see." },
          { id: "i3", text: "nslookup -type=SRV _ldap._tcp.selkirktimber.example", bucket: "t1018", why: "DNS names the Domain Controllers, which are the machines an intruder most wants to find." },
          { id: "i4", text: "Test-Connection SLK-FILE02", bucket: "t1018", why: "Is this machine there at all? No port involved." },
          { id: "i5", text: "nmap -sV -p 445,3389 10.40.12.33", bucket: "t1046", why: "-sV identifies the service on each port. The host was already known." },
          { id: "i6", text: "nmap -p 1-1024 10.40.12.0/24", bucket: "t1046", why: "A port scan. It finds hosts along the way, but the question is what's listening." },
          { id: "i7", text: "Test-NetConnection SLK-FILE02 -Port 445", bucket: "t1046", why: "A one-port check: is SMB open on that machine?" },
          { id: "i8", text: "crackmapexec smb 10.40.12.0/24", bucket: "t1046", why: "SMB enumeration across a range, a tool MITRE names under this technique." },
        ],
        primer: {
          title: "Two close cousins",
          points: [
            "**T1018, Remote System Discovery**, asks what else exists: ping sweeps, `net view` and `net view /domain`, `arp -a`, `nltest /dclist`.",
            "**T1046, Network Service Discovery**, goes a layer deeper: what is running there. Port scans, nmap, SMB enumeration, CrackMapExec.",
            "Vulnerability scanners (Nessus, Qualys, Rapid7) do both as their sanctioned job, across the whole range, every day.",
            "The packets look the same either way, so telling them apart is about assets and identity. An nmap-shaped pattern from a workstation at 02:00 and the same pattern from the security team's scanner on schedule are different stories.",
          ],
          example: {
            label: "A worked pair: one database host",
            lines: [
              "`Resolve-DnsName sql01` tells you sql01 exists. First question.",
              "`Test-NetConnection sql01 -Port 1433` tells you something is listening. Second question.",
            ],
          },
        },
      },
    ],
    // ── Log analysis 1: warm-up on one event's timeline ──
    "disc-la1": [
      {
        kind: "trace",
        title: "Pull the Thread Both Ways",
        prompt: "A 4799 turned up on the mill office PC this morning. Bahar doesn't stop at one event: an event sits in a timeline, and the timeline runs both ways. Go back to where the session started, back again to where the account started, then forward. Click the row that answers each step.",
        lead: "Event 4799, SLK-MILL-03, 10:43:12: Backup Operators read by n.halvorsen, SubjectLogonId 0x4e19a0",
        steps: [
          {
            id: "logon", ask: "Which logon opened the session this event ran in?",
            source: "Security log · SLK-MILL-03 · Event ID 4624 · 10:00 to 11:00",
            columns: ["Time", "TargetUserName", "LogonType", "TargetLogonId", "IpAddress"],
            rows: [
              ["10:02:11", "SYSTEM", "5", "0x3e7", "-"],
              ["10:14:40", "b.tremaine", "2", "0x3a90c", "-"],
              ["10:38:17", "svc-inventory", "3", "0x4dd310", "10.40.2.10"],
              ["10:41:02", "n.halvorsen", "3", "0x4e19a0", "10.40.7.27"],
              ["10:55:20", "n.halvorsen", "3", "0x4e2b18", "10.40.7.27"],
            ],
            answer: 3,
            why: "TargetLogonId here is the SubjectLogonId on the 4799. Logon Type 3 is a network logon, so this session arrived from 10.40.7.27. That's SLK-YARD-07, the scale-house PC.",
            learned: "The session is a network logon from SLK-YARD-07 at 10:41:02",
          },
          {
            id: "origin", ask: "Follow the account back. Where did this user's morning look wrong?",
            source: "VPN gateway · sign-ins · Thursday",
            columns: ["Time", "User", "Source IP", "New for this user?", "Assigned IP"],
            rows: [
              ["07:02:13", "l.ferreira", "198.51.100.71", "No", "10.40.250.11"],
              ["07:44:50", "adm-r.sato", "198.51.100.36", "No", "10.40.250.12"],
              ["08:58:31", "n.halvorsen", "203.0.113.58", "Yes", "10.40.250.18"],
              ["09:40:05", "g.sandoval", "198.51.100.9", "No", "10.40.250.19"],
            ],
            answer: 2,
            why: "A log scaler who works on site signed in over VPN from an address never seen for that account, under 14 minutes before the first whoami, on SLK-YARD-07 at 09:12:04. So the discovery has a beginning: an anomalous sign-in.",
            learned: "The account came in over VPN from a new address at 08:58:31",
          },
          {
            id: "next", ask: "Now forward. Which line is the first to point this session at another machine?",
            source: "Security log · SLK-MILL-03 · Event ID 4688 · SubjectLogonId=0x4e19a0",
            columns: ["Time", "NewProcessName", "CommandLine"],
            rows: [
              ["10:41:20", "whoami.exe", "whoami"],
              ["10:42:02", "ipconfig.exe", "ipconfig /all"],
              ["10:43:09", "powershell.exe", "powershell -c Get-LocalGroupMember 'Backup Operators'"],
              ["10:44:19", "net.exe", "net share"],
              ["10:46:33", "net.exe", "net view \\\\SLK-FILE02"],
              ["10:47:15", "powershell.exe", "powershell -ep bypass -f g.ps1"],
              ["10:48:51", "net.exe", "net group \"Harvest Planners\" /domain"],
            ],
            answer: 4,
            why: "net view against a named server. Everything before it asked about this PC. SLK-FILE02 holds the Bids share, so now you know which way the session is heading.",
            learned: "Next target: SLK-FILE02",
          },
        ],
        primer: {
          title: "Joining a session",
          points: [
            "`SubjectLogonId` on an event names the session it ran in. On the Event 4624 that opened that session, the same value is `TargetLogonId`.",
            "**Logon Type** says how: 2 is at the keyboard, 3 is over the network, 5 is a service, 10 is Remote Desktop.",
            "On a Type 3 or 10 logon, `IpAddress` tells you the next machine to look at.",
            "IDs are only unique on one host, and only until a reboot, so join on host and ID together.",
          ],
          example: {
            label: "A worked join: a server at lunchtime",
            lines: [
              "A 4688 on `FIN-SRV2` has `SubjectLogonId` `0x9c1d0`.",
              "A 4624 on `FIN-SRV2` has `TargetLogonId` `0x9c1d0`, Logon Type 10, from 10.9.4.20.",
              "So the process came from a Remote Desktop session, and 10.9.4.20 is where you look next.",
            ],
          },
        },
      },
    ],
    // ── Reading 5: cloud discovery ──
    "disc-r5": [
      {
        kind: "reactor",
        title: "Three Questions for a Cloud",
        prompt: "Selkirk keeps its aerial survey data in the cloud, and at 11:32 Bahar's phone lights up: the same questions, through an API. Route each call to the question it's asking before it runs off the belt.",
        reactors: [
          { id: "t1580", label: "T1580 Infrastructure", sub: "Which resources exist here?" },
          { id: "t1526", label: "T1526 Services", sub: "Which services, apps and policies are set up?" },
          { id: "t1619", label: "T1619 Storage objects", sub: "What's inside this store?" },
        ],
        items: [
          { id: "i1", text: "DescribeDBClusters", reactor: "t1580", why: "A database cluster is a resource. The call asks which ones exist." },
          { id: "i2", text: "gcloud storage buckets list", reactor: "t1580", why: "Which buckets exist. It doesn't look inside any of them." },
          { id: "i3", text: "GetBucketLocation", reactor: "t1580", why: "A fact about the bucket as a resource, not about its contents." },
          { id: "i4", text: "az storage account list", reactor: "t1580", why: "The storage resources in a subscription." },
          { id: "i5", text: "roadrecon gather", reactor: "t1526", why: "ROADTools collects Azure AD applications and service principals: identity configuration, not machines." },
          { id: "i6", text: "Get-MgApplication -All", reactor: "t1526", why: "Applications registered in the tenant, read through Microsoft Graph." },
          { id: "i7", text: "az account management-group list", reactor: "t1526", why: "Management groups are how a tenant is organised, so they're part of the service map." },
          { id: "i8", text: "ListObjectVersions", reactor: "t1619", why: "Every version of every object in a bucket. You only ask that about a bucket you already found." },
          { id: "i9", text: "aws s3 ls s3://slk-lidar-2026/ --recursive", reactor: "t1619", why: "Behind this command the CLI runs ListObjectsV2. The bucket is known and the question is what's in it." },
          { id: "i10", text: "gcloud storage ls gs://slk-survey-raw/", reactor: "t1619", why: "It returns names, not contents. Reads show up separately in the audit log as storage.objects.get, so after any listing the question is whether reads followed." },
        ],
        primer: {
          title: "Same questions through an API",
          points: [
            "A stolen API key or a compromised identity is a foothold as well. Cloud discovery is the same questioning, done through API calls.",
            "**T1580** finds what exists: `DescribeInstances`, `ListBuckets`, `HeadBucket`, `GetPublicAccessBlock`, `DescribeDBInstances`, `az vm list`, `gcloud compute instances list`. Pacu and TruffleHog are named offensive tools.",
            "**T1526** maps services and identity setup through Microsoft Graph and Azure Resource Manager. Named tools: Stormspotter, ROADTools, AADInternals.",
            "**T1619** looks inside storage: `ListObjectsV2` in S3, List Blobs in Azure.",
            "One such call is routine: Terraform, cost dashboards and CI/CD pipelines make them all day. The signal is the same identity working through many services in minutes.",
          ],
          example: {
            label: "A worked placement: a shared drive service",
            lines: [
              "`GET /drives` returns the drives in a tenant. That's the which-exist question.",
              "`GET /drives/{id}/root/children` returns what's in one drive. That's the what's-inside question.",
              "Neither call has opened a file.",
            ],
          },
        },
      },
      {
        kind: "inspect",
        title: "Read a Finding's Name",
        prompt: "Amazon GuardDuty is the threat detection service watching Selkirk's survey account, and a finding's name says most of what it saw. Open each part of this list before Bahar asks you what one means.",
        artifact: "Threat detection · Finding types · survey account",
        items: [
          { id: "i1", text: "ThreatPurpose:ResourceType/ThreatFamily", tag: "How the name is built", tone: "info", note: "First the purpose of the activity, then the kind of resource affected, then what was seen. Read it left to right." },
          { id: "i2", text: "Recon:IAMUser/MaliciousIPCaller", tag: "Account-level reconnaissance", tone: "warn", note: "An identity's API credentials were used for reconnaissance from an address on a threat list." },
          { id: "i3", text: "Discovery:IAMUser/AnomalousBehavior", tag: "Behaviour model", tone: "warn", note: "No threat list needed. Enumeration-style API use didn't fit what this identity normally does." },
          { id: "i4", text: "Discovery:S3/AnomalousBehavior", tag: "Behaviour model on storage", tone: "warn", note: "No threat list needed. An identity called S3 APIs used to discover resources in a way that didn't fit its normal activity." },
        ],
      },
    ],
    // ── Log analysis 2: warm-up on CloudTrail ──
    "disc-la2": [
      {
        kind: "anatomy",
        title: "Anatomy of a CloudTrail Record",
        prompt: "Before Bahar shows you what happened at 11:32, read an ordinary record: Selkirk's infrastructure pipeline, checking a bucket setting during a plan. Field by field, this is what each one states.",
        source: "AWS CloudTrail · management event · survey account",
        fields: [
          { key: "eventName", value: "GetBucketPublicAccessBlock", label: "What", note: "The event name can differ from the API action name. The S3 API action here is GetPublicAccessBlock." },
          { key: "eventSource", value: "s3.amazonaws.com", label: "Which service" },
          { key: "awsRegion", value: "ca-central-1" },
          { key: "userIdentity.type", value: "AssumedRole", label: "Credential type", note: "Temporary credentials from a role were presented." },
          { key: "userIdentity.arn", value: "arn:aws:sts::111122223333:assumed-role/ci-deploy-role/tf-plan-8841", label: "Role and session", note: "The role name, then the session name. The session name is set when the credentials are issued." },
          { key: "sourceIPAddress", value: "198.51.100.24", label: "From where", note: "Where this call came from. Filtering CloudTrail on this value shows every call from the address." },
          { key: "userAgent", value: "Terraform/1.9.5", label: "Which client", note: "The software that made the call." },
          { key: "readOnly", value: "true", note: "The call changed no state." },
          { key: "managementEvent", value: "true", note: "A control-plane operation: configuration, not stored data." },
          { key: "errorCode", value: "(empty)", note: "No error was recorded, which is how a successful call looks." },
        ],
        summary: "A record gives you what was called, on which service, with which credentials, from where and by what client. Whether that's normal is a separate question: this role runs from the build pipeline's address, through Terraform, on every plan. Knowing that is what lets you compare the next record against it.",
      },
      {
        kind: "worksheet",
        title: "Add Up the Burst",
        prompt: "survey-sync-role runs on one cloud server (an EC2 instance) and uploads the day's drone data at 18:00. That's Wednesday's run at the top of this table. Everything under it happened on Thursday. Work it out from the rows.",
        caption: "CloudTrail · management and S3 data events · userIdentity: survey-sync-role · 9 of 31 Thursday rows shown",
        columns: ["eventTime", "eventSource", "eventName", "sourceIPAddress", "userAgent"],
        rows: [
          ["Wed 18:00:04", "s3", "PutObject", "10.60.2.14", "Boto3/1.34.11"],
          ["Wed 18:00:06", "s3", "PutObject", "10.60.2.14", "Boto3/1.34.11"],
          ["Wed 18:00:09", "s3", "PutObject", "10.60.2.14", "Boto3/1.34.11"],
          ["Thu 11:32:08", "sts", "GetCallerIdentity", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:32:41", "s3", "ListBuckets", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:33:02", "iam", "ListRoles", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:33:20", "kms", "ListKeys", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:33:55", "secretsmanager", "ListSecrets", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:34:10", "iam", "ListUsers", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:34:27", "s3", "GetBucketLocation", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:35:02", "s3", "ListObjects", "203.0.113.58", "Boto3/1.35.2"],
          ["Thu 11:36:15", "secretsmanager", "DescribeSecret", "203.0.113.58", "Boto3/1.35.2"],
        ],
        questions: [
          { id: "svc", q: "How many different services does the Wednesday run touch?", hint: "Read eventSource for the first three rows.", answer: ["1", "one"], why: "One: S3. The job does one thing, so that's the baseline." },
          { id: "burst", q: "How many different services do the Thursday rows touch?", hint: "List each eventSource once, from 11:32 onward.", answer: ["5", "five"], why: "Five: sts, s3, iam, kms and secretsmanager. Any one of those rows would pass as routine. Together they're one identity working through a whole account in about four minutes." },
          { id: "changed", q: "Did any Thursday row change anything? (yes/no)", hint: "Which of these event names would write?", answer: ["no"], why: "All of them read. That's why nothing here failed or tripped a control, and it doesn't make the burst harmless." },
          { id: "pivot", q: "Which value would you filter CloudTrail on to find everything else from this source?", hint: "It's the same on every Thursday row, and it isn't the role.", answer: ["203.0.113.58"], why: "203.0.113.58. It's the VPN address from this morning, so the network morning and the cloud morning are one story." },
        ],
      },
    ],
    // ── Reading 6: looking becomes taking ──
    "disc-r6": [
      {
        kind: "rush",
        title: "Looking or Taking?",
        prompt: "SLK-FILE02 holds the Bids share, and the mill session has just asked about it. Bahar's whole plan depends on one line, so call these fast: is this still looking, or has it become taking?",
        trueLabel: "Looking: Discovery",
        falseLabel: "Taking: Collection",
        target: 10,
        cards: [
          { id: "c1", text: "net view \\\\SLK-FILE02", answer: true, why: "What does this one server share? T1135. Nothing has been read." },
          { id: "c2", text: "robocopy \\\\SLK-FILE02\\Survey C:\\ProgramData\\s /E", answer: false, why: "Bulk copy off a share: T1039, Data from Network Shared Drive." },
          { id: "c3", text: "net share", answer: true, why: "What does this machine share? Still a list." },
          { id: "c4", text: "dir \\\\SLK-FILE02\\Survey /s /b", answer: true, why: "File names only. No file has been opened yet." },
          { id: "c5", text: "copy \\\\SLK-FILE02\\Survey\\*.xlsx C:\\Temp", answer: false, why: "The contents have moved. That's Collection, however small the copy." },
          { id: "c6", text: "PowerView Find-DomainShare across 60 hosts", answer: true, why: "Automated share hunting: wide, but it's still a list of shares." },
          { id: "c7", text: "crackmapexec smb 10.40.2.0/24 --shares", answer: true, why: "Many hosts, one question: what do you share?" },
          { id: "c8", text: "Copy-Item Z:\\* C:\\ProgramData\\s -Recurse", answer: false, why: "PowerShell reading a mounted drive in bulk, one of the odd readers worth watching for." },
          { id: "c9", text: "sharing -l on a Mac", answer: true, why: "The macOS way of listing this machine's shares." },
          { id: "c10", text: "aws s3 ls s3://slk-lidar-2026/ --recursive", answer: true, why: "Listing a bucket's objects is the storage version of dir: still Discovery." },
          { id: "c11", text: "aws s3 cp s3://slk-lidar-2026/ . --recursive", answer: false, why: "Each object is now read with GetObject. The data is moving." },
          { id: "c12", text: "A script opens 400 Office files on a mapped drive", answer: false, why: "Reading the documents themselves. Real groups have collected exactly this." },
          { id: "c13", text: "Get-Content \\\\SLK-FILE02\\C$\\Bids\\terms.txt", answer: false, why: "One file, through an admin share. The contents were read, and C$ makes it worse." },
          { id: "c14", text: "Get-SmbShare", answer: true, why: "PowerShell's list of this machine's shares." },
        ],
        lesson: "Listing tells someone what's there. Reading is when it starts to cost you. Stopping an intruder on the list means nothing has been taken. Stopping them after the copy means the exposure already happened. So the list is the early, cheap signal, and a burst of reads from the same source minutes later confirms the line was crossed.",
        primer: {
          title: "The line between two tactics",
          points: [
            "**T1135, Network Share Discovery**, is still Discovery (TA0007): `net view \\\\remotesystem` for one remote system, `net share` for this machine, `sharing -l` on macOS. CrackMapExec and PowerView automate it.",
            "**T1039, Data from Network Shared Drive**, is Collection (TA0009): reading files from shares already found. menuPass mounted shares with `net use` and pulled data with Robocopy.",
            "A separate tactic means a separate point of commitment, and a very different cost to you.",
            "Correlate the two: share listing against several hosts from one source, then large reads from a UNC path by that same source.",
            "Watch admin shares (`C$`, `ADMIN$`) and atypical readers such as PowerShell or certutil on a mounted drive.",
          ],
          example: {
            label: "A worked line: a document portal",
            lines: [
              "Browsing a folder tree on the portal: titles only. Looking.",
              "Opening the 12 documents under one title: contents read. Taking.",
              "The account, the browser and the portal are the same. Only the verb changed.",
            ],
          },
        },
      },
    ],
    // ── Ordering: warm-up in another setting ──
    "disc-o1": [
      {
        kind: "sequence",
        title: "The Same Climb in the Cloud",
        prompt: "Bahar sketches the intruder's cloud morning as it would run if nobody stopped it. Put these calls in the order an attacker holding one stolen role would make them, from the first question to the last step.",
        items: [
          { id: "b", text: "ListBuckets, DescribeInstances, ListRoles", note: "Now the wider question: what exists in this account?" },
          { id: "e", text: "Sync the objects to a bucket the attacker controls", note: "The data leaves. By now, it's an incident with a disclosure question." },
          { id: "a", text: "GetCallerIdentity", note: "The cloud's whoami. Which identity am I holding?" },
          { id: "d", text: "GetObject, thousands of times", note: "This is where looking stops. The tactic is now Collection." },
          { id: "c", text: "ListObjectsV2 on the survey bucket", note: "One bucket looks worthwhile. What's actually in it?" },
        ],
        order: ["a", "b", "c", "d", "e"],
        doneNote: "Identity, then what exists, then what's inside, then the reads, then out. Every step narrows the question, and the earlier you step in, the less it costs.",
      },
    ],
    // ── Reading 7: detecting discovery ──
    "disc-r7": [
      {
        kind: "hunt",
        title: "One Command Is Nothing, Ten Are a Map",
        prompt: "No alert fired on any of this, and a rule on whoami would only wake you for the helpdesk. Bahar wants something else: every logon session that asked several different questions in a short time. The first line already rounds each event down to a ten-minute slot. Build the rest. Every result you see is really what that line returns.",
        language: "SPL",
        console: "Search",
        start: "index=wineventlog EventCode=4688 earliest=-24h | bin span=10m _time",
        goal: "the sessions looking around on hosts that have no reason to",
        tables: [
          {
            name: "index=wineventlog EventCode=4688 earliest=-24h | bin span=10m _time",
            note: "Native Security log: Event ID 4688, process creation. _time is already rounded to its ten-minute slot.",
            columns: ["_time", "Computer", "SubjectUserName", "SubjectLogonId", "NewProcessName", "CommandLine", "ParentProcessName"],
            rows: [
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}whoami.exe`, "whoami", INV],
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}ipconfig.exe`, "ipconfig /all", INV],
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}net.exe`, "net view", INV],
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}net.exe`, "net share", INV],
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}net1.exe`, "C:\\Windows\\system32\\net1 share", `${S}net.exe`],
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}net.exe`, "net user", INV],
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}net1.exe`, "C:\\Windows\\system32\\net1 user", `${S}net.exe`],
              [`${D}06:00:00`, "SLK-INV-01", "svc-inventory", "0x2f41c", `${S}query.exe`, "query user", INV],
              [`${D}06:00:00`, "SLK-YARD-07", "SLK-YARD-07$", "0x3e7", `${S}ipconfig.exe`, "ipconfig /all", HEALTH],
              [`${D}06:00:00`, "SLK-YARD-07", "SLK-YARD-07$", "0x3e7", `${S}whoami.exe`, "whoami", HEALTH],
              [`${D}06:00:00`, "SLK-MILL-03", "SLK-MILL-03$", "0x3e7", `${S}query.exe`, "query user", HEALTH],
              [`${D}06:00:00`, "SLK-MILL-03", "SLK-MILL-03$", "0x3e7", `${S}ipconfig.exe`, "ipconfig /all", HEALTH],
              [`${D}06:00:00`, "SLK-PLAN-04", "SLK-PLAN-04$", "0x3e7", `${S}net.exe`, "net config workstation", HEALTH],
              [`${D}06:00:00`, "SLK-PLAN-04", "SLK-PLAN-04$", "0x3e7", `${S}net1.exe`, "C:\\Windows\\system32\\net1 config workstation", `${S}net.exe`],
              [`${D}06:00:00`, "SLK-PLAN-04", "SLK-PLAN-04$", "0x3e7", `${S}whoami.exe`, "whoami", HEALTH],
              [`${D}06:00:00`, "SLK-IT-02", "SLK-IT-02$", "0x3e7", `${S}nltest.exe`, "nltest /dsgetdc:selkirktimber.example", HEALTH],
              [`${D}06:00:00`, "SLK-IT-02", "SLK-IT-02$", "0x3e7", `${S}ipconfig.exe`, "ipconfig /all", HEALTH],
              [`${D}08:40:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}whoami.exe`, "whoami", CMD],
              [`${D}08:40:00`, "SLK-PLAN-04", "l.ferreira", "0x6ab10", `${S}ipconfig.exe`, "ipconfig /all", CMD],
              [`${D}08:40:00`, "SLK-PLAN-04", "l.ferreira", "0x6ab10", `${S}notepad.exe`, "notepad network_notes.txt", `${S}explorer.exe`],
              [`${D}08:50:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}net.exe`, "net user l.ferreira /domain", CMD],
              [`${D}08:50:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}net1.exe`, "C:\\Windows\\system32\\net1 user l.ferreira /domain", `${S}net.exe`],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}whoami.exe`, "whoami", CMD],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}ipconfig.exe`, "ipconfig /all", CMD],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}net.exe`, "net user", CMD],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}net1.exe`, "C:\\Windows\\system32\\net1 user", `${S}net.exe`],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}query.exe`, "query user", CMD],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}net.exe`, "net localgroup \"Remote Desktop Users\"", CMD],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}net1.exe`, "C:\\Windows\\system32\\net1 localgroup \"Remote Desktop Users\"", `${S}net.exe`],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}net.exe`, "net config workstation", CMD],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}net1.exe`, "C:\\Windows\\system32\\net1 config workstation", `${S}net.exe`],
              [`${D}09:10:00`, "SLK-YARD-07", "n.halvorsen", "0x7b2c1e", `${S}nltest.exe`, "nltest /dclist:selkirktimber.example", CMD],
              [`${D}09:20:00`, "SLK-PLAN-04", "l.ferreira", "0x6ab10", `${S}whoami.exe`, "whoami", CMD],
              [`${D}09:20:00`, "SLK-YARD-07", "k.lindgren", "0x7c0a44", "C:\\Program Files\\ScaleTicket\\scale.exe", "scale.exe /t 44812", `${S}explorer.exe`],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}whoami.exe`, "whoami", WMI],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}ipconfig.exe`, "ipconfig /all", WMI],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}WindowsPowerShell\\v1.0\\powershell.exe`, "powershell -c Get-LocalGroupMember 'Backup Operators'", WMI],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}net.exe`, "net share", WMI],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}net1.exe`, "C:\\Windows\\system32\\net1 share", `${S}net.exe`],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}net.exe`, "net view \\\\SLK-FILE02", WMI],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}WindowsPowerShell\\v1.0\\powershell.exe`, "powershell -ep bypass -f g.ps1", WMI],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}net.exe`, "net group \"Harvest Planners\" /domain", WMI],
              [`${D}10:40:00`, "SLK-MILL-03", "n.halvorsen", "0x4e19a0", `${S}net1.exe`, "C:\\Windows\\system32\\net1 group \"Harvest Planners\" /domain", `${S}net.exe`],
              [`${D}11:10:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}ipconfig.exe`, "ipconfig /all", CMD],
              [`${D}11:10:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}nltest.exe`, "nltest /dsgetdc:selkirktimber.example", CMD],
              [`${D}11:10:00`, "SLK-PLAN-04", "l.ferreira", "0x6ab10", `${S}netsh.exe`, "netsh wlan show interfaces", CMD],
              [`${D}11:20:00`, "SLK-PLAN-04", "l.ferreira", "0x6ab10", `${S}WindowsPowerShell\\v1.0\\powershell.exe`, "powershell -c Get-ADGroupMember 'Harvest Planners'", CMD],
              [`${D}13:00:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}WindowsPowerShell\\v1.0\\powershell.exe`, "powershell -f Check-Leavers.ps1", CMD],
              [`${D}13:20:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}net.exe`, "net group \"Harvest Planners\" /domain", CMD],
              [`${D}13:20:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}net1.exe`, "C:\\Windows\\system32\\net1 group \"Harvest Planners\" /domain", `${S}net.exe`],
              [`${D}13:20:00`, "SLK-IT-02", "adm-r.sato", "0x91d20", `${S}query.exe`, "query user", CMD],
            ],
          },
          {
            name: "asset_roles.csv",
            note: "Lookup file: one row per host, with its role and whether discovery is part of its job.",
            columns: ["host", "role", "recon_expected"],
            rows: [
              ["SLK-DC01", "Domain Controller", "yes"],
              ["SLK-FILE02", "File server", "no"],
              ["SLK-INV-01", "Asset inventory server", "yes"],
              ["SLK-IT-02", "Helpdesk workstation", "yes"],
              ["SLK-KIOSK-01", "Shared yard kiosk", "no"],
              ["SLK-MILL-03", "Mill office PC", "no"],
              ["SLK-PLAN-04", "Harvest planner laptop", "no"],
              ["SLK-YARD-07", "Log yard scale PC", "no"],
            ],
          },
        ],
        rungs: [
          {
            id: "tools", ask: "Line 2: keep only the built-in tools that ask questions.",
            choices: [
              { id: "a", text: "| search CommandLine=\"*net*\"", why: "24 rows, and the wrong ones: notepad network_notes.txt and netsh wlan matched, every net1 line came along, and whoami, ipconfig and nltest are gone. A piece of text isn't a list of tools.", apply: { op: "where", col: "CommandLine", test: "has", value: "net" } },
              { id: "b", text: "| search NewProcessName IN (\"*\\\\whoami.exe\", \"*\\\\ipconfig.exe\", \"*\\\\net.exe\", \"*\\\\net1.exe\", \"*\\\\query.exe\", \"*\\\\nltest.exe\")", why: "44 rows. net1.exe is the child net.exe starts for most of its jobs, so those commands now appear twice with different text. One question counts as two, and the yard session would score 10 instead of 7.", apply: { op: "where", col: "NewProcessName", test: "in", value: [`${S}whoami.exe`, `${S}ipconfig.exe`, `${S}net.exe`, `${S}net1.exe`, `${S}query.exe`, `${S}nltest.exe`] } },
              { id: "c", text: "| search NewProcessName IN (\"*\\\\whoami.exe\", \"*\\\\ipconfig.exe\", \"*\\\\net.exe\", \"*\\\\query.exe\", \"*\\\\nltest.exe\")", right: true, why: "34 rows, each tool once per run. Filtering on the program keeps notepad and netsh out, and leaving net1.exe out stops one command counting twice.", apply: { op: "where", col: "NewProcessName", test: "in", value: [`${S}whoami.exe`, `${S}ipconfig.exe`, `${S}net.exe`, `${S}query.exe`, `${S}nltest.exe`] } },
              { id: "d", text: "| search SubjectUserName!=adm-*", why: "42 rows, because nothing was filtered on what ran. And you've just excused any intruder holding an admin account. Admins are in this data on purpose: the next lines deal with them.", apply: { op: "where", col: "SubjectUserName", test: "notin", value: ["adm-r.sato"] } },
            ],
          },
          {
            id: "stack", ask: "Line 3: one row for each different command, in each session, in each window.",
            choices: [
              { id: "a", text: "| stats count by CommandLine", why: "13 rows: whoami ran 7 times, ipconfig /all 8 times. That's a popularity chart. Who, where and when have all gone.", apply: { op: "summarize", by: ["CommandLine"], as: "count" } },
              { id: "b", text: "| stats count by _time, SubjectLogonId, CommandLine", why: "31 rows, and 0x3e7 now shows five commands in the 06:00 slot. That's the health agent on four machines, all running as SYSTEM with the same logon ID. A logon ID only means something on its own host.", apply: { op: "summarize", by: ["_time", "SubjectLogonId", "CommandLine"], as: "count" } },
              { id: "c", text: "| stats count by Computer, SubjectUserName, SubjectLogonId, CommandLine", why: "34 rows, and the window has gone. Look at 0x91d20: adm-r.sato has six commands in that session, spread from 08:40 to 13:20. Without a time slot, a slow working day adds up like a sweep.", apply: { op: "summarize", by: ["Computer", "SubjectUserName", "SubjectLogonId", "CommandLine"], as: "count" } },
              { id: "d", text: "| stats count by _time, Computer, SubjectUserName, SubjectLogonId, CommandLine", right: true, why: "34 rows: one for each different command, in each session, on each host, in each slot. Run whoami ten times and it would still be one row here, so repeats can't pass for breadth.", apply: { op: "summarize", by: ["_time", "Computer", "SubjectUserName", "SubjectLogonId", "CommandLine"], as: "count" } },
            ],
          },
          {
            id: "breadth", ask: "Line 4: each row is now one different command. Turn that into a number per session and window.",
            choices: [
              { id: "a", text: "| stats count by Computer", why: "5 rows. SLK-YARD-07 shows 9, but that's seven from one session and two from the health agent. Sessions and windows were the whole point, and they've gone.", apply: { op: "summarize", by: ["Computer"], as: "count" } },
              { id: "b", text: "| stats count by _time, Computer, SubjectUserName, SubjectLogonId", right: true, why: "13 rows, and count now means how many different commands that session ran in that slot. Most say 1 or 2. Three stand out: 6, 7 and 5.", apply: { op: "summarize", by: ["_time", "Computer", "SubjectUserName", "SubjectLogonId"], as: "count" } },
              { id: "c", text: "| stats count by CommandLine", why: "13 rows, one per command, saying how many sessions ran it. Useful for a baseline, but it can't point at a session.", apply: { op: "summarize", by: ["CommandLine"], as: "count" } },
            ],
          },
          {
            id: "cut", ask: "Line 5: read the numbers, then draw a first line. You'll tune it properly afterwards.",
            choices: [
              { id: "a", text: "| where count>=2", why: "9 rows. The health agents and adm-r.sato's ordinary work came along. Two different commands in one slot is someone checking a thing.", apply: { op: "where", col: "count", test: "in", value: ["2", "3", "4", "5", "6", "7", "8", "9", "10"] } },
              { id: "b", text: "| where count>=5", right: true, why: "3 rows: 6, 7 and 5. Everything else here is 2 or lower, so the gap is wide enough for a first line. It's one day of data, so it's a starting point, and you'll test it properly next.", apply: { op: "where", col: "count", test: "in", value: ["5", "6", "7", "8", "9", "10"] } },
              { id: "c", text: "| where count>=7", why: "One row, and the session with 5 is gone. A line drawn just under the loudest result misses the quieter one.", apply: { op: "where", col: "count", test: "in", value: ["7", "8", "9", "10"] } },
              { id: "d", text: "| where count>=10", why: "Nothing. Ten makes a good saying, but nobody here asked ten different questions in one slot. A threshold comes from your data.", apply: { op: "where", col: "count", test: "in", value: ["10"] } },
            ],
          },
          {
            id: "role", ask: "Line 6: the numbers can't say whose job this is. Bring in what can.",
            choices: [
              { id: "a", text: "| search Computer!=SLK-INV-01", why: "2 rows, and they're the right two, but you got there by deleting a host by name. Nothing records why, and the next tool means another edit. A row needs a reason to go.", apply: { op: "where", col: "Computer", test: "notin", value: ["SLK-INV-01"] } },
              { id: "b", text: "| lookup asset_roles.csv host AS Computer OUTPUT role recon_expected", right: true, why: "The same 3 rows, each with its host's role. The file says discovery is the inventory server's job, and it isn't the job of a scale PC or a mill office PC. A query can't compute that.", apply: { op: "join", table: "asset_roles.csv", left: "Computer", right: "host", hideKey: true } },
              { id: "c", text: "| table Computer count", why: "3 rows and fewer columns. Tidier isn't better informed: nothing here says whose job this is.", apply: { op: "project", cols: ["Computer", "count"] } },
            ],
          },
          {
            id: "final", ask: "Line 7: leave only what nobody can explain.",
            choices: [
              { id: "a", text: "| search recon_expected=no", right: true, why: "2 rows: one account, two hosts, an hour and a half apart, on a scale PC and a mill office PC. Neither has a reason to be asking. Each command was harmless, and together they're a map.", apply: { op: "where", col: "recon_expected", test: "eq", value: "no" } },
              { id: "b", text: "| search recon_expected=yes", why: "One row: the inventory server, the one you've just explained. Handy for checking the lookup, but it isn't what you came for.", apply: { op: "where", col: "recon_expected", test: "eq", value: "yes" } },
              { id: "c", text: "| search role=\"Log yard*\"", why: "One row. The yard PC was the one you already suspected, and the mill session has dropped out. Filter on the reason, not on the name you expect.", apply: { op: "where", col: "role", test: "has", value: "Log yard" } },
            ],
          },
        ],
        expect: 2,
        lesson: "Keep the tools, stack by window, host and session, count what's different, draw a line, then add what the numbers can't know. In real SPL, stats dc(CommandLine) does the two stats lines at once. Fixed slots have a gap: a sweep from 09:58 to 10:03 lands in two of them, and streamstats with time_window closes it. A loop inside one PowerShell process is a single row here, so this stack needs LDAP and script logging beside it. On Sysmon Event ID 1 the same search uses Image and LogonId.",
        primer: {
          title: "Counting different questions",
          points: [
            "Event **4688** logs each new process, and its `CommandLine` stays empty unless the 'Include command line in process creation events' policy is on. Sysmon Event ID **1** records the same process with its command line by default.",
            "A session is one logon, named by `SubjectLogonId` on 4688 and `LogonId` on Sysmon 1. The ID only means something on one host: `0x3e7` is SYSTEM on every Windows machine.",
            "In SPL, Splunk's search language, `bin span=10m _time` rounds each event down to its slot, so `stats` can count per window.",
            "`stats count by a, b` gives one row per combination. A second `stats` over those rows counts combinations, so repeats stop inflating the number.",
            "`net.exe` hands most jobs to a child process, `net1.exe`, so one command can create two rows.",
          ],
          example: {
            label: "A worked stack: print jobs",
            lines: [
              "`... | stats count by printer, job_type` gives one row per printer and job type.",
              "`| stats count by printer` over that gives how many different job types each printer ran.",
              "A printer that ran one job a thousand times now counts as 1.",
            ],
          },
        },
      },
      {
        kind: "tune",
        title: "How Many Questions, How Fast?",
        prompt: "The hunt worked by hand, and five-in-a-slot was only a first line. Bahar replays the idea over 30 days of Selkirk sessions, with the intruder's two sessions and four test runs mixed in, and with the inventory server and the scanner already taken out. The dials start on the saying, ten commands in ten minutes. Deploy it, then find the rule that catches all six.",
        eventColumn: "Session in the 30-day replay",
        dials: [
          { id: "distinct", label: "Different discovery commands at or above", short: "commands", min: 2, max: 14, step: 1, start: 10 },
          { id: "minutes", label: "All within minutes, at or below", short: "minutes", unit: "min", min: 5, max: 60, step: 1, start: 10, dir: "below" },
        ],
        events: [
          { id: "b1", label: "Thursday's session on SLK-YARD-07", bad: true, values: { distinct: 7, minutes: 6 } },
          { id: "b2", label: "Thursday's session on SLK-MILL-03", bad: true, values: { distinct: 5, minutes: 8 } },
          { id: "b3", label: "Test run: scripted sweep", bad: true, values: { distinct: 11, minutes: 1 } },
          { id: "b4", label: "Test run: hands on keyboard, reading as it goes", bad: true, values: { distinct: 6, minutes: 26 } },
          { id: "b5", label: "Test run: four quick checks, then silence", bad: true, values: { distinct: 4, minutes: 3 } },
          { id: "b6", label: "Test run: slow script with sleeps", bad: true, values: { distinct: 9, minutes: 14 } },
          { id: "n1", label: "Helpdesk: one ticket, worked between calls", bad: false, values: { distinct: 4, minutes: 41 } },
          { id: "n2", label: "New-PC build script on a fresh laptop", bad: false, values: { distinct: 6, minutes: 2 } },
          { id: "n3", label: "Network engineer chasing a fault", bad: false, values: { distinct: 5, minutes: 30 } },
          { id: "n4", label: "Logon script on the mill PCs", bad: false, values: { distinct: 3, minutes: 1 } },
          { id: "n5", label: "IT admin checking one user's rights", bad: false, values: { distinct: 3, minutes: 4 } },
          { id: "n6", label: "Vendor support session on the scale software", bad: false, values: { distinct: 5, minutes: 12 } },
        ],
        goal: { catch: 6, maxFalse: 2 },
        deploys: 4,
        lesson: "Four different commands within 26 to 29 minutes catches all six with two false alarms. Ten in ten caught one. A round 30 lets the network engineer in, and dropping to three wakes you for a logon script. The two left, the build script and the vendor session, can't be tuned away because they look exactly like a sweep. Moving the dial further would cost you a real session, so those two belong on an allowlist, with an owner.",
        primer: {
          title: "Three questions and two dials",
          points: [
            "**Is this identity or host expected to do this?** Check it against what you know about the account and the machine.",
            "**Does the volume and breadth fit a person, a tool or a sweep?** A person touches a handful over minutes. A legitimate tool touches everything on a fixed schedule from a documented identity. A sweep touches many in a tight burst, with no scheduled reason.",
            "**Does it correlate with anything?** Discovery is rarely the incident itself. It's the leading indicator: what came before it, and what followed?",
            "A rule of this kind has two dials: how many different commands, and in how long. Tighter misses slow sessions, looser pages you for honest ones.",
          ],
          example: {
            label: "A worked dial: failed logons",
            lines: [
              "Rule: 20 failures in 5 minutes. Replay: 2 of 3 password sprays caught, no false alarms.",
              "Rule: 12 failures in 5 minutes. Replay: 3 of 3 caught, one kiosk with a stale password fires.",
              "Keep the second, and write the kiosk in the rule's notes.",
            ],
          },
        },
      },
      {
        kind: "sort",
        title: "Narrow Enough to Keep?",
        prompt: "The rule is live, and the first things it caught are Selkirk's own tools. Bahar's allowlist has a queue of suggestions from around the company. Keep the ones that leave an intruder nowhere to stand, and send the rest back.",
        buckets: [
          { id: "keep", label: "Narrow: add it" },
          { id: "back", label: "Too wide: send it back" },
        ],
        items: [
          { id: "i1", text: "svc-inventory, on SLK-INV-01 only, 06:00 to 06:20 daily, owner Asset team", bucket: "keep", why: "Account, host, schedule and owner. That same account from any other host still alerts." },
          { id: "i2", text: "Every account whose name starts svc-", bucket: "back", why: "A naming pattern is not an authorisation, and a stolen service account is a favourite way to blend in." },
          { id: "i3", text: "The scanner SLK-SCAN-01, Fridays 01:00 to 05:00, change CHG-2204", bucket: "keep", why: "A known appliance, its window, and a record of who agreed to it." },
          { id: "i4", text: "Everything from the server network", bucket: "back", why: "An intruder who reaches one server inherits the exemption for all of them." },
          { id: "i5", text: "ci-deploy-role, from the CI runner's address, through Terraform", bucket: "keep", why: "One role, one source, one client. The role's credentials used from anywhere else still alert." },
          { id: "i6", text: "Any net.exe between 00:00 and 06:00", bucket: "back", why: "Time alone explains nothing. Night is when nobody's watching, so it's a bad thing to exempt." },
          { id: "i7", text: "adm-r.sato, any host, any time", bucket: "back", why: "A person's name isn't a schedule. If that account is stolen, this entry is the intruder's cover." },
          { id: "i8", text: "svc-bkp on SLK-BKP-01, share listing only, nightly at 22:00, owner Backup team", bucket: "keep", why: "Specific in all four directions, and it says what the job is allowed to do." },
        ],
        primer: {
          title: "When the rule is right and nothing is wrong",
          points: [
            "A **false positive** is a rule misfiring on something it wasn't meant to catch. A **benign true positive** is a rule correctly seeing real activity that happens to be authorised.",
            "Discovery produces benign true positives more than almost any other tactic. Most of what such a rule fires on is the SOC's own tooling doing this work on purpose.",
            "Scanners (Nessus, Qualys, Rapid7) look like T1046. Asset tools (SCCM, Intune) read local groups and logged-on users. Terraform and CloudFormation look like T1580. Backup software looks like T1135. Helpdesk scripts audit accounts.",
            "An **allowlist** names the specific accounts, hosts and schedules authorised to do this. You alert on everything outside it.",
          ],
          example: {
            label: "A worked entry: a database backup job",
            lines: [
              "Entry: account `svc-sqlbk`, host `DB-BK1`, 23:00 to 23:30, owner DBA team.",
              "Each part narrows it. `svc-sqlbk` used from another host still alerts.",
              "So does `svc-sqlbk` at noon.",
            ],
          },
        },
      },
    ],
    // ── Boss warm-up: the label, and why it matters ──
    "disc-ac1": [
      {
        kind: "queue",
        title: "Correct Rule, Right Label",
        prompt: "Friday morning. Thursday's two sessions are contained and the rule is watching. Five alerts sit in the queue, and Bahar wants each one closed with the right label or sent on. Before you decide, check who owns it and whether the owner confirms it.",
        console: "SIEM · Discovery rules · Status: New",
        actions: [
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          { id: "a1", time: "Fri 01:04", severity: "Medium", rule: "Internal port scan across subnets", entity: "SLK-SCAN-01",
            fields: [{ k: "targets", v: "10.40.0.0/16" }, { k: "ports", v: "1-1024" }, { k: "host role", v: "Vulnerability scanner" }, { k: "allowlist", v: "CHG-2204, Fridays 01:00 to 05:00" }, { k: "owner says", v: "Confirmed, this is the weekly scan" }],
            context: "The scanner really did scan. The rule did exactly what it was built to do.", answer: "btp", why: "Real scanning, correctly detected, and authorised by a named owner. Nothing misfired, so it isn't a false positive: record the change number and close." },
          { id: "a2", time: "Fri 07:12", severity: "Low", rule: "Discovery command: whoami", entity: "SLK-PLAN-04",
            fields: [{ k: "account", v: "l.ferreira" }, { k: "CommandLine", v: "notepad whoami_notes.txt" }, { k: "NewProcessName", v: "notepad.exe" }],
            context: "The rule matches the string whoami anywhere in the command line.", answer: "fp", why: "No discovery happened: someone opened a text file. The rule misfired on a file name, so this is a real false positive, and the fix is to match on the process." },
          { id: "a3", time: "Thu 16:20", severity: "Medium", rule: "Cloud API sweep by one identity", entity: "ci-deploy-role",
            fields: [{ k: "calls", v: "44 Describe and List calls, 3 services" }, { k: "sourceIPAddress", v: "198.51.100.24" }, { k: "userAgent", v: "Terraform/1.9.5" }, { k: "pipeline", v: "Run 8862, merged by the platform team" }, { k: "owner says", v: "Confirmed, drift check on apply" }],
            context: "The source is the CI runner's address and the run ID matches the pipeline's log.", answer: "btp", why: "The sweep is real, and it's what Terraform does on every apply. The record, the run ID and the owner all agree." },
          { id: "a4", time: "Fri 02:31", severity: "Medium", rule: "Internal port scan across subnets", entity: "SLK-PLAN-04",
            fields: [{ k: "targets", v: "10.40.2.0/24" }, { k: "ports", v: "445, 3389" }, { k: "host role", v: "Harvest planner laptop" }, { k: "allowlist", v: "None for this host" }, { k: "owner says", v: "IT has no scan planned from this host" }],
            context: "Same rule as the scanner, and from the outside the same traffic.", answer: "esc", why: "The packets look like the weekly scan. The source, the time and the missing owner don't. Same packets, different owner: only the asset list can tell them apart." },
          { id: "a5", time: "Fri 05:47", severity: "Medium", rule: "Share enumeration from one source", entity: "SLK-MILL-03",
            fields: [{ k: "account", v: "svc-bkp" }, { k: "command", v: "net view \\\\SLK-FILE02" }, { k: "host role", v: "Mill office PC" }, { k: "allowlist", v: "svc-bkp on SLK-BKP-01, nightly at 22:00" }, { k: "owner says", v: "Backup team: not ours" }],
            context: "The account is on the allowlist. The host and the time aren't.", answer: "esc", why: "A familiar account in the wrong place, at the wrong time, and its owner disowns it. An allowlist entry only covers the whole entry: account, host and schedule together." },
        ],
      },
    ],
  },
};
