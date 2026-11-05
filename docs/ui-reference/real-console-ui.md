# Real analyst consoles: UI reference for simulated labs

Purpose: help front-end developers make simulated labs look and behave like the real consoles.
Confidence markers: **[doc]** = confirmed in vendor documentation; **[obs]** = widely seen in public screenshots, demos and community write-ups, but not quoted from docs; **[unsure]** = an approximation. Hex values are approximate visual matches, not official brand tokens.

General rule for all labs: copy layout, density, vocabulary and interaction patterns. Do **not** copy logos, product names in the chrome, or trademarked iconography. Use "Falcon-style" or "EDR console" framing in the UI.

---

## 1. CrowdStrike Falcon

**Layout.** A thin top bar holds a hamburger/"Falcon" menu that opens a large left-side mega-menu (Endpoint security, Next-Gen SIEM, Fusion SOAR, Host setup and management, etc.). Content pages are full width under the bar. Dark theme is the norm in most screenshots [obs]; light mode exists. Density is high: compact tables, 13px text, small pill badges.

**Colour.** Background near-black/charcoal (`#14161a` to `#1f2228`), panels a step lighter (`#262a31`). Brand accent is Falcon red (`#e8002d` to `#ec0b2f`) [obs], used sparingly (logo, primary buttons, critical). Severity set (5 levels) [doc]: **Critical, High, Medium, Low, Informational**. Shown as a coloured pill or a small coloured bar/dot next to the text: Critical deep red/magenta, High orange-red, Medium amber, Low blue/teal, Informational grey [unsure on exact tints].

**Main screens and names.**
- *Endpoint detections* (now part of the unified **Detections**/alerts view). Typical columns [obs, partly doc via API field names]: Severity, Detect time, Hostname, Tactic & technique (e.g. "Credential Access via OS Credential Dumping"), Triggering file, Status (New / In progress / True positive / False positive / Closed / Ignored), Assigned to, Detect ID. API fields confirm tactic, technique, technique ID, severity name, file name, file path, device hostname, composite ID [doc].
- *Detection details*: left = **process tree**, right = details panel. Known labels: Command line, File path, SHA256, MD5, User name, Process ID / Parent process ID, IOA name, IOA description, Tactic & technique, Technique ID, **Objective** (Falcon's own kill-chain buckets: "Gain Access", "Explore", "Keep Access", "Follow Through", "Contact Controlled Systems", "Falcon Detection Method") [obs]. Encoded PowerShell is shown decoded alongside the original [doc]. View toggles: Process tree / Process table / Process activity [obs].
- *Process tree node*: process image name (e.g. `WINWORD.EXE`), with small icons/counters for disk, network, registry and DNS operations; the triggering node is outlined in severity colour; injected processes are shown as linked nodes [doc: tree shows Outlook > Word > PowerShell and injection into notepad.exe].
- *Host management*: columns Hostname, Type (Workstation/Server/DC), OS version, Status (Online/Offline), Last seen, First seen, Sensor version, Host groups, Prevention policy, Containment status [obs]. Action **Network contain** (lift containment later) [doc].
- *Real Time Response (RTR)*: dark terminal panel opened from a host or detection ("Connect to host"). Prompt mimics the OS, e.g. `C:\>` on Windows, `/ ` path on Linux, with the host name in the panel header [obs]. Commands are RTR built-ins, not native shell [doc via API]: read-only `cat cd clear env eventlog filehash getsid help history ipconfig ls mount netstat ps reg query`; active responder adds `get kill rm cp mv mkdir memdump reg set/delete restart shutdown xmemdump encrypt`; admin adds `put run runscript put-and-run` [role split varies by source].
- *Falcon Fusion (SOAR) workflows*: canvas builder at Fusion SOAR > Workflows; vertical flow of **Trigger** -> **Condition** (if/else, e.g. Severity >= High) -> **Action** (Contain device, Run RTR script, Send email, Request human input), plus loops and parallel branches [doc].

**Recognisable.** Black canvas + single red accent; horizontal/vertical process tree with tiny activity icons; "Objective" and "Tactic & technique" wording; RTR terminal inside the page.

**Game ideas.**
1. *Tree climb*: the detection opens with only the triggering node visible; each correct "expand parent" pick (based on command line evidence) reveals the next ancestor until patient zero.
2. *RTR budget*: a limited number of RTR commands per host; scoring rewards the minimal command set that proves the case (`ps`, `netstat`, `filehash`, `reg query ...\Run`).
3. *Fusion builder puzzle*: drag Trigger/Condition/Action blocks to automate containment without isolating a domain controller (a trap condition).
4. *Containment clock*: "Network contain" is available, but containing the wrong host costs points.

---

## 2. SentinelOne Singularity

**Layout.** Left vertical icon sidebar (Dashboard, Incidents/Threats, Activity, Sentinels (endpoints), Visibility/Event Search, Ranger, Settings). Main area: filter bar on top, dense table, right-side or full-page detail. Dark is the default in most current screenshots [obs]; the brand is purple.

**Colour.** Background dark navy/purple-black (`#1b1530` to `#221c3a`) [unsure]; accent SentinelOne purple (`#6b2fd6` to `#7f3fe4`) [obs]. Threat confidence is the main "severity": **Malicious** (red, `#e5484d`) vs **Suspicious** (orange/amber, `#f5a524`) shown as shield icons/badges [obs]. Newer Singularity Operations Center also uses Critical/High/Medium/Low.

**Main screens and names.**
- *Threats/Incidents list*: columns [obs] Threat details (file name + path), Status (Mitigated / Not mitigated / Marked as resolved), AI Confidence Level (Malicious/Suspicious), Analyst Verdict, Incident Status, Endpoints, Reported time, Classification (Ransomware, Trojan, Backdoor...), Detection engine (Static AI / Behavioral AI / Reputation...), Policy (Protect/Detect).
- *Threat Center (threat details)* [doc]: header status bar with **Threat Status**, **AI Confidence Level**, **Analyst Verdict** (True positive / False positive / Suspicious / Undefined) and **Incident Status** (Unresolved / In progress / Resolved). Tabs: **Overview** (Network history first/last seen, Threat details: Initiating process, Detection engine, static vs dynamic, Classification, signed/verified, Endpoint snapshot, Threat Indicators mapped to MITRE), **Explore** (attack Storyline as Process Tree or table: processes, files, registry, network, child processes), **Timeline** (analyst, console and Agent activity, notes).
- *Mitigation actions* [doc]: Kill, Quarantine, Remediate, **Rollback**, Network Quarantine (Disconnect from network), Add to Exclusions/Blocklist, Mark as resolved, Add note, Remote Shell.
- *Storyline*: every event carries a **Storyline ID** (TrueContext ID / SrcProcStorylineId) that groups the whole chain; one query by Storyline ID returns all related processes, files and network events [doc].
- *Deep Visibility / Event Search*: query bar, time range picker, results with Event type, Process name, Process ID, Path, Command line, User, Storyline ID, TrueContext ID [doc partly]; "Save new set" creates a **Watchlist** [doc]. Modern query language is S1QL / PowerQuery, e.g. `EventType = "Process Creation" AND SrcProcName = "powershell.exe"` [obs].
- *Remote Shell*: full native shell (cmd/PowerShell or bash), enabled per policy, session password + 2FA required, fully audited [doc].

**Recognisable.** Purple accent, shield-shaped confidence badges, the word "Storyline", the **Rollback** button.

**Game ideas.**
1. *Storyline stitching*: scattered event cards share hidden Storyline IDs; the player pivots on the ID to pull the whole chain together.
2. *Verdict vs status*: player must set both Analyst Verdict and Incident Status correctly; mismatches (True positive + Resolved without mitigation) are flagged.
3. *Rollback decision*: ransomware scenario where Rollback is correct only after Network Quarantine.
4. *Remote Shell gate*: entering the shell requires the "session password" given in the briefing, then a timed hunt for persistence.

---

## 3. Microsoft Defender XDR

**Layout.** Fluent UI: top bar (Microsoft Defender, search, settings), collapsible **left navigation** ("quick launch") with groups such as Investigation & response > **Incidents & alerts** > Incidents / Alerts, Hunting > **Advanced hunting**, Assets > Devices/Identities [doc]. Light theme by default, dark available. Medium density, generous whitespace, command bar of icon+text buttons above tables.

**Colour.** Light background `#faf9f8`/white, text `#323130`, accent Microsoft blue `#0078d4`. Severity values [doc]: **High, Medium, Low, Informational**; shown as a small filled bar icon (3 bars) plus the word: High dark red `#a4262c`/`#d13438`, Medium orange `#ca5010`/`#f7630c`, Low yellow `#ffaa44` [unsure exact], Informational grey. Priority score 0-100 [doc]: red > 85, orange 15-85, grey < 15.

**Main screens and names.**
- *Incident queue* (Incidents & alerts > Incidents) [doc]: default last week; filters Status (New / In progress / Resolved), Severity, Incident assignment, Service/detection sources, Tags, Categories, Entities, Device groups, OS platform, Classification, Automated investigation state, Associated threat. Columns (customisable) [obs]: Incident name, Incident Id, Tags, Severity, Priority score, Investigation state, Categories, Impacted assets, Active alerts, Service sources, Detection sources, First activity, Last activity, Last update time, Assigned to, Classification, Determination. Auto names like "Multi-stage incident on multiple endpoints reported by multiple sources" [doc]. Clicking a row (not the name) opens a right summary pane with up/down arrows [doc].
- *Incident page tabs* [doc]: **Attack story**, Alerts, Assets (Devices, Users, Mailboxes, Apps, Cloud resources), Investigations, **Evidence and Response** (verdict Malicious/Suspicious/Clean + remediation status, Approve/Reject), Summary, Similar incidents, Activities. Right pane: Incident details (assignment, ID, classification, categories, first/last activity).
- *Attack story*: left = alert list, centre = **incident graph** with a **Play** control that animates alerts and nodes over time, filters (Severity, Status, Service sources), Entity types toggle, node context menu with "Go hunt" and "View blast radius" [doc].
- *Alert story*: sections **What happened**, **Actions taken**, **Related events**; a vertical **process tree** of indented rows (`explorer.exe` > `winword.exe` > `powershell.exe -enc ...`) with expandable cards, alert-triggering rows highlighted with a red/orange left icon; right pane with alert state, details, MITRE techniques [doc + obs].
- *Advanced hunting*: schema tree on the left (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, EmailEvents, IdentityLogonEvents, AlertInfo, AlertEvidence...), KQL editor top-centre with **Run query**, time range, results grid below with Export and "Link to incident" [doc/obs].

**Recognisable.** White Fluent cards, blue links, three-bar severity icon, the animated incident graph with round entity icons.

**Game ideas.**
1. *Replay the graph*: hit Play, pause at each step, and predict the next node before it appears.
2. *KQL ladder*: start from `DeviceProcessEvents | where FileName == "powershell.exe"` and refine (`ProcessCommandLine has "-enc"`) to hit an exact row count.
3. *Evidence verdicts*: approve or reject pending remediation actions; approving deletion of a clean file costs points.
4. *Queue triage race*: sort 20 incidents by priority, then compare with the hidden priority score.

---

## 4. Microsoft Sentinel

**Layout.** Two homes: Azure portal blade (moving out of the Azure portal by 31 March 2027) and the Defender portal (same look as section 3) [doc]. Azure blade: left resource menu (Overview, Logs, News & guides, Search, **Threat management > Incidents**, Workbooks, Hunting, Notebooks, Entity behavior, Threat intelligence, Content management, Configuration > Analytics, Automation, Data connectors). Light by default; Azure dark theme common in screenshots.

**Colour.** Azure blue `#0078d4`, page `#ffffff`, blade header grey. Severity values: **High, Medium, Low, Informational**, shown as coloured text pill / coloured left band [doc mentions "severity color band"]: High red `#e81123`/`#d13438`, Medium orange `#ff8c00`, Low yellow `#fce100`, Informational grey [unsure exact].

**Main screens and names.**
- *Incidents grid*: KPI tiles on top (Open incidents, New incidents, Active incidents; by severity), filter pills (Severity, Status, Owner, Product name), columns [obs]: Severity, Incident ID, Title, Alerts, Product names, Created time, Last update time, Owner, Status (New / Active / Closed), Tactics, Tags. Right details pane with Owner/Status/Severity dropdowns and **View full details**.
- *Incident details page* [doc]: top button bar **Tasks**, **Activity log**, **Logs**; **Incident actions** (Run playbook, Create automation rule, Create team). Left panel: basic info, Evidence (Events, Alerts, Bookmarks), Entities, **Investigate** button. Tabs **Overview** (widgets: Incident timeline, Similar incidents with "Similarity reason", Entities, Top insights) and **Entities** (side pane cards Info, Timeline, Insights).
- *Investigation graph* (Investigate): round entity nodes (account, host, IP, file, URL) connected to alert nodes; hover an entity to get **exploration queries** ("Related alerts", "Services created by account"...); added results join with dotted lines; parallel **Timeline** strip at the bottom; **Events>** opens the raw query [doc]. Limited to incidents up to 30 days old [doc].
- *Logs (KQL)*: tables pane left (SecurityEvent, SigninLogs, AuditLogs, CommonSecurityLog, Syslog, SecurityAlert, SecurityIncident...), editor with **Run**, Time range, Save, Share, results grid with chart toggle. Bookmark rows via **Add bookmark** [doc].

**Recognisable.** Azure blade chrome, KPI tiles over the grid, the dark-navy investigation graph with circular icons and dotted "expanded" links.

**Game ideas.**
1. *Exploration query choice*: on each entity, three exploration queries are offered; only one reveals the next pivot. Wrong picks add noise nodes.
2. *Bookmark to prove*: the incident is "closed" only when the player bookmarks the 3 log rows that prove each stage.
3. *Classification gate*: closing requires True positive / Benign positive / False positive + reason; the grader checks evidence.

---

## 5. Splunk Enterprise Security

**Layout.** Splunk app bar at top (black `#1a1c20` header with app menu: Security Posture, **Incident Review**, Investigations, Security Intelligence, Security Domains, Audit, Search, Configure). ES 8.x moves to a new **Mission Control**-style "Analyst queue". Classic Incident Review: light page, filter area across the top, timeline histogram, dense table. Search & Reporting: light by default; dark theme exists for dashboards [obs].

**Colour.** Splunk accent green/lime (`#65a637` legacy, `#5cc05c`) and Splunk pink/magenta in newer branding (`#ed0080`) [unsure]. Urgency values [doc]: **Critical, High, Medium, Low, Informational** (plus Unknown), shown as a coloured icon + word: critical red `#d6563c`, high orange `#f1813f`, medium yellow `#f8be34`, low green `#53a051`, info blue `#006d9c` [obs from Splunk palettes, unsure]. Urgency = correlation search severity x asset/identity priority [doc].

**Main screens and names.**
- *Incident Review* default columns [doc via Splunk answer]: (expand arrow), (checkbox), **Time, Security Domain, Title, Urgency, Status, Owner, Actions**. Filters: Urgency, Status (New, In Progress, Pending, Resolved, Closed), Owner, Security Domain (Access, Endpoint, Network, Threat, Identity, Audit), Tag, Search, Time. Buttons **Edit Selected**, **Add Selected to Investigation**. Expanded row shows Description, Additional Fields (src, dest, user...), Related Investigations, Correlation Search, History, Contributing Events (**View all ... contributing events** link), Adaptive Responses, Next Steps [obs].
- *Actions menu*: Add Event to Investigation, Run Adaptive Response Actions, Share Notable Event, Suppress Notable Events, Build Event Type, Show Source, field-level Investigate in asset/identity dashboards [obs].
- *Search & Reporting*: search bar with SPL, time range picker ("Last 24 hours"), green **Search** magnifier button, mode (Fast/Smart/Verbose); below: Events / Patterns / Statistics / Visualization tabs, histogram timeline, left **fields sidebar** (Selected fields host/source/sourcetype, Interesting fields with counts), events list with `_time` and raw text, key=value highlighting.

**Recognisable.** Black app bar, urgency icons, histogram above results, the left "Interesting fields" list, SPL pipes.

**Game ideas.**
1. *SPL builder*: start with `index=wineventlog EventCode=4625` and pipe `| stats count by src_ip, user | where count>20`; target the attacker IP.
2. *Urgency maths*: player predicts urgency from severity x asset priority before the table reveals it.
3. *Notable triage shift*: 15 notables, a timer, and status transitions (New > In Progress > Resolved) with mandatory comment.

---

## 6. Elastic Security (Kibana)

**Layout.** Kibana chrome: top header with breadcrumbs and global search; collapsible left nav (Security: Dashboards, Rules, **Alerts**, Attack discovery, Findings, Cases, Investigations > **Timelines**, Explore > Hosts/Network/Users). Light by default, dark mode popular. Medium density, EUI components.

**Colour.** EUI palette: primary blue `#0077cc`/`#07c`, Elastic teal accent `#00bfb3`, danger `#bd271e`. Severity: **Critical, High, Medium, Low** shown as coloured dot + word and as "Risk score" number 0-100: critical `#e7664c`/red, high `#da8b45` orange, medium `#d6bf57` yellow, low `#54b399` green [obs, unsure].

**Main screens and names.**
- *Alerts page*: KPI charts (Severity levels donut, Alerts by name, Top alerts by host.name), filters (Status Open/Acknowledged/Closed), alerts table columns [obs]: @timestamp, Rule, Assignees, Severity, Risk score, Reason, host.name, user.name, process.name, file.name, source.ip, destination.ip. Row actions: expand (flyout), **Investigate in timeline**, **Analyze event** (cube icon), Session view, more actions [doc].
- *Alert flyout*: tabs Overview / Table / JSON; sections About, Investigation guide, Insights (entities, threat intel, correlations, prevalence), Highlighted fields.
- *Visual event analyzer* [doc]: graph of process **cubes**; children under parents with time gaps; **event pills** per `event.category` ("3 file", "2 registry", "1 alert"); analysed event outlined light blue; toolbar: Process Tree info, Legend, Data view, Time filter, list icon opening the preview panel; process details: event count, timestamp, file path, process.pid, user name/domain.
- *Timeline* [doc]: bar pinned at the bottom of every page; KQL query bar + query builder (drop fields horizontally = AND, vertically = OR); **Correlation** tab (EQL sequences), **ES|QL** tab, event renderers toggle, pin events, notes.

**Recognisable.** Bottom "Untitled timeline" bar, isometric process cubes, ECS dotted field names (`process.parent.name`).

**Game ideas.**
1. *Drag to hunt*: drag `host.name` and `process.name` chips into the Timeline drop zone to build the query (AND vs OR placement matters).
2. *EQL sequence lock*: write `sequence by host.name [process where ...] [network where ...]` to unlock the next stage.
3. *Cube walk*: in the analyzer, click pills to find the one registry event that proves persistence.

---

## 7. Palo Alto Cortex XDR

**Layout.** Left icon nav rail (Dashboards, Incidents/Cases, Investigation > Query Builder/XQL, Response > Action Center, Assets, Settings). Dark default in most screenshots [obs]. Incident view: header with score, severity, status, assignee; tabs Overview, Key Assets & Artifacts, Alerts & Insights, Timeline, Executions [obs; Cortex 5.x renames incidents/alerts to "cases/issues" [doc]].

**Colour.** Dark slate/navy (`#1a2029` to `#232b38`) [unsure], accent Cortex green/teal (`#00c08b`) and Palo Alto orange (`#fa582d`) for brand. Severity: **Critical, High, Medium, Low, Informational** as coloured pills; incidents also show a numeric **Incident score** (SmartScore) [obs].

**Main screens and names.**
- *Incidents table* columns [obs]: Incident ID, Incident name/Description, Score, Severity, Status (New, Under investigation, Resolved - True Positive / Resolved - False Positive / Resolved - Other...), Assignee, Alerts breakdown, Hosts, Users, Creation time, Last updated.
- *Causality View* [doc]: header card (alert name, host, user), **causality chain** drawn left to right with the **Causality Group Owner (CGO)** on the left; process nodes with badges for **Injected Node** and **Remote IP address**; alert nodes attached to the process that triggered them; up to nine extra branches; "Showing Partial Causality" flag. Right-click: Show parents and children, Hide branch, Add to block list/allow list, Terminate process, Quarantine, Terminate process by hash. Hover = **Process Information** pop-up.
- *Information overview* [doc]: alert nodes show name, source, timestamp, severity, action taken, tags, MITRE; process nodes show path, parent PID, SHA256, username, **WildFire Score** and report.
- *Forensics Highlights* strip [doc]: MITRE ATT&CK, Script Engines, Alerts, Process, Network, File, Registry, System Calls, RPC Calls.
- *All Events table* below the chain [doc]: tabbed (Prevention Actions, Process, File, Network, Registry...), up to 100,000 events, right-click pivots "Show rows 30 days prior/after".
- *Timeline view*: CGO and host top-left, events and BIOCs on a time axis [doc]. Query language: **XQL** (`dataset = xdr_data | filter event_type = ENUM.PROCESS | fields actor_process_image_name, action_process_command_line`).

**Recognisable.** Left-to-right causality chain starting from a CGO, WildFire verdicts, the Forensics Highlights strip under the graph.

**Game ideas.**
1. *Find the CGO*: given a mid-chain alert, the player must identify which process "owns" the chain (not the OS parent).
2. *WildFire verdict reveal*: request a verdict per hash with a limited number of lookups.
3. *Branch pruning*: hide benign branches to leave only the malicious path; score on precision.

---

## 8. Wireshark

**Layout** [doc]: Menu, Main toolbar, **Filter toolbar** ("Apply a display filter ... <Ctrl-/>" field, green when valid, red when invalid, yellow when suspicious), then three stacked panes: **Packet List**, **Packet Details**, **Packet Bytes** (newer versions add a **Packet Diagram** pane), and a **Status bar** (expert info LED, file name, "Packets: N · Displayed: N", profile). Follows the OS theme; light on most screenshots, dark mode on macOS/Windows 4.x.

**Colour.** Default coloring rules [obs]: TCP light purple `#e7e6ff`, UDP light blue `#daeeff`, HTTP light green `#e4ffc7`, ARP/ICMP pale yellow/pink (`#fafae6`/`#fce0ff`), TCP RST/bad checksum/errors black `#12272e` row with red text `#ff5f5f`, SYN/FIN grey `#a0a0a0`. Selected row: system highlight blue. No severity concept; **Expert Info** severities Chat (blue), Note (cyan), Warn (yellow), Error (red).

**Names.** Default Packet List columns [obs]: **No., Time, Source, Destination, Protocol, Length, Info**. Details pane is a tree: `Frame 42: 74 bytes on wire`, `Ethernet II, Src: ..., Dst: ...`, `Internet Protocol Version 4, Src: ..., Dst: ...`, `Transmission Control Protocol, Src Port: 49712, Dst Port: 443, Seq: 1, Ack: 1, Len: 517`, `Transport Layer Security`. Bytes pane: offset column (`0000`), 16 hex bytes, ASCII column; selecting a details field highlights its bytes. Key menus: Analyze > Follow > TCP Stream; Statistics > Conversations / Protocol Hierarchy / Endpoints; File > Export Objects > HTTP. Display filters: `ip.addr==10.0.0.5`, `tcp.flags.syn==1 && tcp.flags.ack==0`, `http.request.method=="POST"`, `dns.qry.name contains "xyz"`.

**Recognisable.** Pastel rows, three stacked panes, the filter bar turning green/red as you type.

**Game ideas.**
1. *Filter golf*: reach a target packet set in the fewest filter characters; filter bar colour gives live validity feedback.
2. *Byte hunt*: click a field in the details tree and find the matching bytes (or the reverse) to extract a flag hidden in a payload.
3. *Follow the stream*: open Follow TCP Stream to read a C2 beacon and identify the interval and User-Agent.

---

## Sources (internal reference only, not for students)

- https://learn.microsoft.com/en-us/defender-xdr/incident-queue
- https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents
- https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents
- https://www.crowdstrike.com/blog/tech-center/remote-remediation-real-time-response/
- https://www.crowdstrike.com/blog/tech-center/generate-your-first-detection/
- https://www.crowdstrike.com/tech-hub/endpoint-security/falcon-fusion-with-real-time-response/
- https://www.crowdstrike.com/falcon-platform/falcon-fusion/
- https://developer.crowdstrike.com/ngsiem/fusion-soar/
- https://developer.crowdstrike.com/api-reference/collections/real-time-response-admin/
- https://www.mintlify.com/CrowdStrike/psfalcon/api/real-time-response
- https://docs.blinkops.com/docs/integrations/crowdstrike/actions/run-command-on-a-single-host.md
- https://glama.ai/mcp/servers/@CrowdStrike/falcon-mcp/blob/04e441121e86b5468f7abaa4a7e644d58ddda8ee/falcon_mcp/resources/detections.py
- https://www.sentinelone.com/blog/feature-spotlight-introducing-the-new-threat-center/
- https://www.sentinelone.com/blog/rapid-threat-hunting-with-deep-visibility-feature-spotlight/
- https://www.sentinelone.com/press/sentinelone-releases-full-remote-shell-capabilities/
- https://docs.limacharlie.io/5-integrations/extensions/third-party/sentinelone/
- https://docs.splunk.com/Documentation/ES/5.0.1/User/Triagenotableevents
- https://docs.splunk.com/Documentation/ES/7.0.0/Admin/CustomizeIR
- https://community.splunk.com/t5/Splunk-Enterprise-Security/Splunk-Enterprise-Security-Why-is-the-Incident-Review-dashboard/m-p/280073
- https://help.splunk.com/en/splunk-enterprise-security-7/mission-control/investigate-and-respond-to-threats/triage-incidents
- https://www.elastic.co/guide/en/security/current/visual-event-analyzer.html
- https://www.elastic.co/guide/en/security/current/timelines-ui.html
- https://cortex-docs.paloaltonetworks.com/cortex-xdr-3.x/cortex-xdr-3.x-documentation/investigate-and-respond-to-incidents/investigate-alerts/alert-investigation-views/causality-view
- https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/investigate-and-respond-to-cases/investigate-issues/causality-view
- https://www.wireshark.org/docs/wsug_html_chunked/ChUseMainWindowSection.html
