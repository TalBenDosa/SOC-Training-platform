import type { RoomExperience } from "./types";

// "Operation Chain of Custody" for the "log-management" room (rooms-batch-04.ts).
// Script: docs/campaign/07-log-management.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Halden Retail (fictional), a card-taking retailer. Lab data differs from the
// graded tasks: the storage worksheet uses 2,000 EPS at 400 bytes (q2), the
// retention match never asks for a five-month-old event (q3), the tampering
// lab is a Linux auth.log compared with its central copy and never shows
// Windows 1102 or 104 (la1, flag), and the drill decodes an audit-policy
// change (4719) on another host.
export const LOG_MANAGEMENT: RoomExperience = {
  roomId: "log-management",
  codename: "Operation Chain of Custody",
  theme: "pipeline",
  handler: { name: "Grace Liu", role: "SIEM Engineer, Halden Retail" },
  briefing: [
    "Halden Retail. Four hundred stores, one payment network, two million log lines an hour.",
    "Every login, every card swipe, every blocked connection writes a line somewhere.",
    "Grace Liu runs the pipeline that brings them all to one place, and keeps them safe.",
    "Follow a log from the moment it is written to the moment it becomes evidence.",
  ],
  mission: "Follow logs end to end: read raw formats, collect and normalise them, size and retain them, catch tampering by comparing copies, then work the alert an attacker hoped nobody would see.",
  estimate: "~45 min",
  look: { primary: "#14b8a6", secondary: "#60a5fa", warn: "#f43f5e" },
  scene: "logriver",
  layout: "stage",
  story: {
    intro: { title: "Two Million Lines an Hour", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-intro-6e8851d4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-intro-19cdda72.jpg" },
    afterStation: {
      pipeline: { title: "One Language", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-ch2-1bd97d1c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-ch2-76288654.jpg" },
      tamper: { title: "The Copy They Could Not Reach", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-ch3-68dd6a6d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-ch3-d792d8fb.jpg" },
      cleared: { title: "Chain of Custody", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-finale-6264a615.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-management/chain-of-custody-finale-7f27084d.jpg" },
    },
  },
  stations: [
    {
      id: "raw",
      label: "Every Log Tells a Story",
      topic: "What a log is · the fields in every entry · log sources · Syslog, JSON, CEF, LEEF",
      tagline: "Read raw lines from four kinds of source and pull out what matters",
      building: "archive",
      taskIds: ["log-mgmt-r1"],
    },
    {
      id: "pipeline",
      label: "Collect and Normalise",
      topic: "Agents, syslog and APIs · normalisation and ECS · the log lifecycle",
      tagline: "Work on the syslog collector, then teach every source to speak one language",
      building: "factory",
      taskIds: ["log-mgmt-r2", "log-mgmt-q1", "log-mgmt-q4"],
    },
    {
      id: "store",
      label: "Store and Retain",
      topic: "Events per second · storage sizing · retention rules (PCI-DSS, HIPAA, SOX, GDPR)",
      tagline: "Size the storage, then decide how long each kind of log must live",
      building: "vault",
      taskIds: ["log-mgmt-q2", "log-mgmt-q3"],
    },
    {
      id: "tamper",
      label: "Tamper Watch",
      topic: "Log tampering · central, immutable storage · SIEM vs log aggregator",
      tagline: "An attacker wiped a server's log. The central copy remembers",
      building: "control",
      taskIds: ["log-mgmt-r3"],
    },
    {
      id: "cleared",
      label: "The Cleared Log",
      topic: "Reading an anti-forensics alert on a domain controller",
      tagline: "Someone emptied the most important log on the network",
      building: "ticket",
      taskIds: ["log-mgmt-la1", "log-mgmt-flag1"],
      boss: true,
    },
  ],
  personas: {
    "log-mgmt-q1": { name: "Grace Liu", role: "SIEM Engineer", line: "Three sources, three names for the same IP field. What is the step that fixes that called?" },
    "log-mgmt-q4": { name: "Grace Liu", role: "SIEM Engineer", line: "The new firewall cannot run any agent. How do we get its logs?" },
    "log-mgmt-q2": { name: "Victor Sandoval", role: "IT Finance Manager", line: "I need a storage number for the budget. Give me a day's worth of raw logs." },
    "log-mgmt-q3": { name: "Grace Liu", role: "SIEM Engineer", line: "The attacker's first login was months ago. Before you search, tell me what to expect." },
  },
  briefings: {
    // ── Reading 1: what logs are, sources, formats ──
    "log-mgmt-r1": [
      {
        kind: "sort",
        title: "Name That Format",
        prompt: "Every vendor writes logs its own way. Read each raw line and name its format.",
        buckets: [
          { id: "syslog", label: "Syslog" },
          { id: "json", label: "JSON" },
          { id: "cef", label: "CEF" },
          { id: "leef", label: "LEEF" },
        ],
        items: [
          { id: "s1", text: "Nov  4 08:12:44 sw-core-02 sshd[2211]: Accepted publickey for ops from 10.8.1.4 port 52211 ssh2", bucket: "syslog", why: "Timestamp, host, program[pid]: free text after the colon. Classic syslog." },
          { id: "j1", text: "{\"ts\":\"2026-11-04T08:12:44Z\",\"user\":\"m.osei\",\"action\":\"download\",\"file\":\"q3_forecast.xlsx\"}", bucket: "json", why: "Named fields in braces: structured JSON, easy for machines to parse." },
          { id: "c1", text: "CEF:0|Fortinet|FortiGate|7.4|13|traffic|3|src=10.8.4.21 dst=203.0.113.50 dpt=443 act=accept", bucket: "cef", why: "CEF:0, then vendor|product|version|id|name|severity, then key=value pairs." },
          { id: "l1", text: "LEEF:2.0|IBM|QRadar|7.5|AuthFail|src=10.8.4.21\tusrName=svc_print", bucket: "leef", why: "LEEF: QRadar's format, a pipe header and tab-separated attributes." },
          { id: "s2", text: "<134>Nov  4 08:13:02 fw-store-118 kernel: DROP IN=eth1 SRC=198.51.100.61 DST=10.8.4.9 DPT=3389", bucket: "syslog", why: "The <134> in front is the syslog priority. Still one line of text per event." },
          { id: "j2", text: "{\"eventTime\":\"2026-11-04T08:14:10Z\",\"eventName\":\"ConsoleLogin\",\"sourceIPAddress\":\"203.0.113.88\"}", bucket: "json", why: "A cloud audit record (AWS CloudTrail style): JSON again." },
        ],
      },
      {
        kind: "worksheet",
        title: "Pull the Fields",
        prompt: "Whatever the format, every entry answers the same questions: when, where, what, who. Pull the answers out of these raw lines.",
        caption: "Raw lines from Halden Retail, 08:12-08:14",
        columns: ["#", "raw line"],
        rows: [
          ["1", "Nov  4 08:12:44 sw-core-02 sshd[2211]: Accepted publickey for ops from 10.8.1.4 port 52211 ssh2"],
          ["2", "{\"ts\":\"2026-11-04T08:12:44Z\",\"user\":\"m.osei\",\"action\":\"download\",\"file\":\"q3_forecast.xlsx\"}"],
          ["3", "CEF:0|Fortinet|FortiGate|7.4|13|traffic|3|src=10.8.4.21 dst=203.0.113.50 dpt=443 act=accept"],
        ],
        questions: [
          { id: "host", q: "Line 1: which host wrote it (the source)?", hint: "In syslog, the host name comes right after the timestamp.", answer: ["sw-core-02"], why: "The source: which device generated the record." },
          { id: "actor", q: "Line 2: who is the actor?", hint: "Look for the user field.", answer: ["m.osei"], why: "The actor: who caused the event." },
          { id: "port", q: "Line 3: which destination port did the firewall allow?", hint: "In CEF, dpt is the destination port.", answer: ["443"], why: "dpt=443 and act=accept: an allowed HTTPS connection. Details like these are what you search on." },
        ],
      },
      {
        kind: "sort",
        title: "Where Did It Come From?",
        prompt: "Logs come from four kinds of source. Sort each record by where it was written.",
        buckets: [
          { id: "endpoint", label: "Endpoint" },
          { id: "network", label: "Network device" },
          { id: "app", label: "Application" },
          { id: "cloud", label: "Cloud platform" },
        ],
        items: [
          { id: "win", text: "A Windows logon event on a store PC", bucket: "endpoint", why: "Endpoints write their own event logs." },
          { id: "fw", text: "A blocked connection at the store's firewall", bucket: "network", why: "Firewalls log every allowed and denied connection." },
          { id: "nginx", text: "An nginx access log line for the web shop", bucket: "app", why: "Web servers and databases log application activity." },
          { id: "ct", text: "An AWS CloudTrail record of a new access key", bucket: "cloud", why: "Cloud platforms log every API call." },
          { id: "sw", text: "A switch reporting a port going down", bucket: "network", why: "Network devices log link and traffic events." },
          { id: "lin", text: "/var/log/auth.log on a Linux server", bucket: "endpoint", why: "Linux servers are endpoints too." },
        ],
      },
    ],
    // ── Reading 2: collection, normalisation, lifecycle ──
    "log-mgmt-r2": [
      {
        kind: "pathway",
        title: "Follow the DROP Line",
        prompt: "fw-store-118 just wrote a DROP line for a probe on RDP. Grace wants to see it in the SIEM, searchable by source.ip, with a copy the attacker cannot reach. Walk the line there, hop by hop.",
        goal: "Take one firewall log line from the device to the end of its life",
        nodes: [
          { id: "fw", label: "fw-store-118", sub: "writes the DROP line", x: 12, y: 50 },
          { id: "agent", label: "Agent on the firewall", sub: "install a forwarder", x: 14, y: 14 },
          { id: "col", label: "log-col-01", sub: "rsyslog, UDP 514", x: 34, y: 28 },
          { id: "loc", label: "Local log only", sub: "stay on the device", x: 30, y: 82 },
          { id: "norm", label: "Normaliser", sub: "SRC= becomes source.ip", x: 50, y: 52 },
          { id: "idx", label: "SIEM hot index", sub: "searchable", x: 70, y: 28 },
          { id: "ana", label: "Rules and analysts", sub: "detect, search", x: 86, y: 52 },
          { id: "arch", label: "Archive tier", sub: "cheaper storage", x: 70, y: 74 },
          { id: "purge", label: "Purge", sub: "retention ends", x: 50, y: 88 },
        ],
        edges: [["fw", "agent"], ["fw", "col"], ["fw", "loc"], ["col", "norm"], ["norm", "idx"], ["idx", "ana"], ["ana", "arch"], ["arch", "purge"]],
        route: ["fw", "col", "norm", "idx", "ana", "arch", "purge"],
        notes: {
          fw: "Firewalls and switches cannot run agents, so they push their syslog out. The line leaves the device the moment it is written.",
          col: "rsyslog listens on UDP 514. Plain UDP has no delivery guarantee, so a burst or a busy link can drop events silently; watch the collector's own drop counter.",
          norm: "The raw line says SRC=198.51.100.61, another product says srcip. Normalising renames both to source.ip so one search covers every firewall.",
          idx: "Written to the index, the line is now searchable in seconds, and a copy exists where a root user on the store firewall cannot reach.",
          ana: "A detection rule and an analyst both query the index. Repeated drops on 3389 from one outside address is the kind of line they look for.",
          arch: "After the hot window the line moves to cheaper storage. PCI wants a year kept, with the last three months immediately searchable.",
          purge: "Only when the retention period ends is the line deleted. Deleting earlier destroys evidence you might need a year later.",
        },
        traps: {
          agent: "Appliances cannot run an agent, which is why agentless syslog exists. Pushing a forwarder onto the firewall is not an option here.",
          loc: "A log that stays on the device is the copy an attacker with root wipes. Without forwarding there is nothing to compare it against.",
        },
        lesson: "A log is safe only after it leaves the device: collect it, normalise it to one language, index it, then retain and finally delete it on schedule. Break any link and the evidence is gone when you need it.",
      },
      {
        kind: "match",
        title: "Speak ECS",
        prompt: "Each source names the same thing differently. Map each vendor field to its Elastic Common Schema (ECS) field.",
        pairs: [
          { id: "srcip", left: "FortiGate: srcip", right: "source.ip", why: "Every source address ends up in one field, so one search covers all firewalls." },
          { id: "user", left: "Windows 4624: TargetUserName", right: "user.name", why: "Whoever logged on, whatever the OS." },
          { id: "dst", left: "CEF: dst", right: "destination.ip", why: "The address the connection went to." },
          { id: "act", left: "CloudTrail: eventName", right: "event.action", why: "What was done: ConsoleLogin, CreateAccessKey, and so on." },
          { id: "outcome", left: "sshd: 'Accepted' or 'Failed'", right: "event.outcome", why: "success or failure, the same word for every source." },
        ],
      },
      {
        kind: "sequence",
        title: "Life of a Log",
        prompt: "One firewall line, from birth to deletion. Put its lifecycle in order.",
        items: [
          { id: "store", text: "Written to the SIEM's index", note: "Store" },
          { id: "gen", text: "fw-store-118 writes the DROP line", note: "Generate" },
          { id: "del", text: "Purged when the retention period ends", note: "Delete" },
          { id: "norm", text: "SRC= becomes source.ip", note: "Normalise" },
          { id: "col", text: "rsyslog on log-col-01 receives it on UDP 514", note: "Collect" },
          { id: "ret", text: "Moved to archive storage after 90 days", note: "Retain" },
          { id: "ana", text: "A detection rule and an analyst search it", note: "Analyse" },
        ],
        order: ["gen", "col", "norm", "store", "ana", "ret", "del"],
        doneNote: "Generate, collect, normalise, store, analyse, retain, delete. Break any link and the evidence is gone when you need it.",
      },
    ],
    // Drill before the storage question.
    "log-mgmt-q2": [
      {
        kind: "worksheet",
        title: "Storage Budget",
        prompt: "Before the budget meeting, size Halden's payment network logs. Work the numbers.",
        caption: "Payment network · measured volume",
        columns: ["measure", "value"],
        rows: [["events per second (EPS)", "2,000"], ["average event size", "400 bytes"], ["seconds in a day", "86,400"], ["SIEM compression saving", "75%"]],
        questions: [
          { id: "bps", q: "How many bytes arrive every second?", hint: "EPS × event size: 2,000 × 400.", answer: ["800000", "800,000", "800000 bytes", "800 KB"], why: "800,000 bytes, about 0.8 MB, every single second." },
          { id: "day", q: "How many gigabytes of raw logs is that per day? (1 GB = 1,000,000,000 bytes)", hint: "800,000 × 86,400 = 69,120,000,000 bytes.", answer: ["69.12", "69.1", "69", "69.12 GB"], why: "About 69 GB of raw logs a day from one network." },
          { id: "comp", q: "After the 75% compression saving, how many GB per day are actually stored?", hint: "Keep 25%: 69.12 × 0.25.", answer: ["17.28", "17.3", "17", "17.28 GB"], why: "About 17 GB a day. Multiply by the retention period and you have the storage bill." },
        ],
      },
    ],
    // Drill before the retention question.
    "log-mgmt-q3": [
      {
        kind: "match",
        title: "Retention Rules",
        prompt: "How long a log must live is a compliance decision. Match each regulation to its retention rule.",
        pairs: [
          { id: "pci", left: "PCI-DSS (card payments)", right: "At least 12 months; the last 3 months immediately searchable", why: "Older months may sit in cheaper archive storage." },
          { id: "hipaa", left: "HIPAA (US healthcare)", right: "Security documentation kept 6 years", why: "Most healthcare organisations apply the same 6 years to security audit logs." },
          { id: "sox", left: "SOX (US financial reporting)", right: "Audit records kept 7 years", why: "Logs that support financial controls are commonly kept 7 years too." },
          { id: "gdpr", left: "GDPR (EU data protection)", right: "No fixed minimum: keep only as long as necessary", why: "Many organisations settle on about 12 months for security logs." },
        ],
      },
    ],
    // ── Reading 3: tampering, immutable storage, SIEM vs aggregator ──
    "log-mgmt-r3": [
      {
        kind: "tune",
        title: "Tamper Alarm",
        prompt: "Grace compares every server's local auth.log with the SIEM's forwarded copy, hour by hour. Set the alarm: how much of the central copy must be missing locally, and how big must the hour be, before it counts as tampering?",
        eventColumn: "Host and hour",
        dials: [
          { id: "miss", label: "Lines missing locally", short: "missing", unit: "%", min: 0, max: 100, step: 5, start: 10 },
          { id: "lines", label: "Lines in the central copy", short: "central", unit: " lines", min: 0, max: 2000, step: 50, start: 100 },
        ],
        events: [
          { id: "t1", label: "ops-api-02 · 01:00 hour, local file empty", bad: true, values: { miss: 100, lines: 1180 } },
          { id: "t2", label: "ops-api-02 · 02:00 hour, local file empty", bad: true, values: { miss: 100, lines: 395 } },
          { id: "t3", label: "pos-gw-12 · only lines for one account gone", bad: true, values: { miss: 64, lines: 920 } },
          { id: "t4", label: "db-card-02 · file truncated mid-hour", bad: true, values: { miss: 52, lines: 610 } },
          { id: "t5", label: "fw-store-118 · a few blocks of lines removed", bad: true, values: { miss: 48, lines: 530 } },
          { id: "n1", label: "ops-api-02 · 00:00 hour, copies match", bad: false, values: { miss: 0, lines: 205 } },
          { id: "n2", label: "kiosk-07 · rebooted, almost no logs yet", bad: false, values: { miss: 100, lines: 6 } },
          { id: "n3", label: "web-shop-02 · logrotate moved lines at midnight", bad: false, values: { miss: 38, lines: 800 } },
          { id: "n4", label: "log-col-01 · forwarder a little behind", bad: false, values: { miss: 12, lines: 340 } },
          { id: "n5", label: "web-shop-02 · busy hour, copies match", bad: false, values: { miss: 0, lines: 3100 } },
          { id: "n6", label: "backup-nas-01 · local logging off by design", bad: false, values: { miss: 100, lines: 240 } },
        ],
        goal: { catch: 5, maxFalse: 0 },
        deploys: 3,
        lesson: "The central copy is the witness: a local file missing a large share of an hour the SIEM saw is tampering. Set the share just above log rotation and lag, and the size just above idle or by-design hosts, and a wipe cannot hide.",
      },
      {
        kind: "sort",
        title: "Aggregator or SIEM?",
        prompt: "A log aggregator stores and searches. A SIEM also detects. Sort each capability.",
        buckets: [
          { id: "agg", label: "Any log aggregator" },
          { id: "siem", label: "Only a SIEM" },
        ],
        items: [
          { id: "search", text: "Show all logs from pay-app-03 between 2 and 3 a.m.", bucket: "agg", why: "Store and search: the aggregator's core job." },
          { id: "corr", text: "Fire when 5 failed logins are followed by a success from one IP", bucket: "siem", why: "Correlation across events is what a SIEM adds." },
          { id: "store", text: "Keep 90 days of firewall logs, indexed", bucket: "agg", why: "Storage and indexing." },
          { id: "ti", text: "Flag a known-bad IP the moment it appears in any log", bucket: "siem", why: "Threat intelligence matching, built in." },
          { id: "mitre", text: "Tag a detection with its ATT&CK technique", bucket: "siem", why: "MITRE ATT&CK mapping is a SIEM feature." },
          { id: "case", text: "Group three related alerts into one incident", bucket: "siem", why: "Case management." },
        ],
      },
    ],
    // Drill before the graded alert: a different anti-forensics event.
    "log-mgmt-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of an Audit Policy Change",
        prompt: "Clearing logs is one way to hide. Turning auditing off is another. Grace shows you event 4719 from a file server, field by field.",
        source: "Windows Security log · FS02-HALDEN · Event ID 4719",
        fields: [
          { key: "EventID", value: "4719", label: "What happened", note: "4719: the system audit policy was changed. Windows logs this before the change stops future logging." },
          { key: "TimeCreated", value: "2026-11-04T02:41:07.338Z" },
          { key: "Computer", value: "FS02.halden.local" },
          { key: "SubjectUserName", value: "it.temp04", label: "Who changed it", note: "The account that made the change. Is it an admin who should touch audit policy?" },
          { key: "SubjectDomainName", value: "HALDEN" },
          { key: "SubjectLogonId", value: "0x1b7c44", label: "Which session", note: "Identifies the logon session that made the change." },
          { key: "CategoryId", value: "%%8274", label: "Which category", note: "Object Access: auditing of file and share access." },
          { key: "SubcategoryGuid", value: "{0CCE9224-69AE-11D9-BED3-505054503030}", label: "Which subcategory", note: "The File Share subcategory: logging of who opens which share." },
          { key: "AuditPolicyChanges", value: "%%8448, %%8450", label: "What changed", note: "Success removed, failure removed: file-share access on this server is no longer logged at all." },
        ],
        summary: "At 02:41, it.temp04 switched off auditing of file-share access on FS02. Nothing was cleared, but from now on nothing will be written. Turning off the cameras is as suspicious as wiping the tape.",
      },
    ],
  },
};
