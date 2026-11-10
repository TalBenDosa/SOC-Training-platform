import type { RoomExperience } from "./types";

// "Operation Intake" for the "log-sources-integration" room.
// Script: docs/campaign/26-log-sources-integration.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Vantage Telecom (fictional). Lab data differs from the graded tasks: the
// transport sort never shows CEF landing in one blob (q1); the silent-source
// console is rsyslog over TLS with an expired CA on Linux, not Winlogbeat on
// Windows (q3); the normalisation sheet maps fields and reads a grok pattern,
// it doesn't ask why normalisation matters (q2) or how to store time (q4); and
// the drill is a LEEF event, not la1's PAN-OS CEF line or its port (flag1).
export const LOG_SOURCES_INTEGRATION: RoomExperience = {
  roomId: "log-sources-integration",
  codename: "Operation Intake",
  theme: "ingest",
  handler: { name: "Owen Fischer", role: "SIEM Onboarding Engineer, Vantage Telecom" },
  briefing: [
    "Vantage Telecom. 340 log sources, five transports, three schemas, and one SIEM that only knows what reaches it.",
    "Owen Fischer onboards every source. A log that never arrives, arrives as one blob, or arrives with the wrong clock is a blind spot with a dashboard on top.",
    "Follow a log from the device that wrote it to the field you search on.",
    "Open the intake.",
  ],
  mission: "Match sources to the transports that carry them, debug a silent rsyslog-over-TLS source, map vendor fields onto a common schema and read a grok pattern, then take apart a LEEF event before the graded CEF one.",
  estimate: "~40 min",
  look: { primary: "#c084fc", secondary: "#34d399", warn: "#f43f5e" },
  scene: "facilitylogsourcesintegration",
  layout: "facility",
  story: {
    intro: { title: "Only What Reaches It", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-intro-02c0e162.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-intro-d8ea85ec.jpg" },
    afterStation: {
      sources: { title: "Running Isn't Arriving", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-ch2-a57c6f5e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-ch2-e62e5243.jpg" },
      agents: { title: "One Name for One Fact", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-ch3-06de281c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-ch3-1d4a63e1.jpg" },
      cef: { title: "Header, Then Extension", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-finale-a40987c6.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-sources-integration/intake-finale-7dbac943.jpg" },
    },
  },
  stations: [
    {
      id: "sources",
      label: "Where Logs Come From",
      topic: "Six source families · syslog UDP/TCP/TLS, WEF, agents, API pulls",
      tagline: "Match each source to how its logs travel",
      building: "archive",
      taskIds: ["log-src-r1"],
    },
    {
      id: "agents",
      label: "The Silent Source",
      topic: "Collection agents and pipelines · why a source goes quiet",
      tagline: "Find out why a server stopped sending",
      building: "control",
      taskIds: ["log-src-r2", "log-src-q3"],
    },
    {
      id: "parse",
      label: "Parse and Normalise",
      topic: "Parsers, grok, common schemas (ECS, OCSF, ASIM) · time zones",
      tagline: "Turn five vendors' names into one schema",
      building: "lab",
      taskIds: ["log-src-r3", "log-src-q1", "log-src-q2", "log-src-q4"],
    },
    {
      id: "cef",
      label: "Read the Wire Format",
      topic: "CEF and LEEF headers and extensions",
      tagline: "Take apart a LEEF event, then the graded CEF one",
      building: "ticket",
      taskIds: ["log-src-la1", "log-src-flag1"],
      boss: true,
    },
  ],
  personas: {
    "log-src-q1": { name: "Owen Fischer", role: "SIEM Onboarding Engineer", line: "PAN-OS CEF over syslog, and it lands as one big message field. Transport or format?" },
    "log-src-q2": { name: "Owen Fischer", role: "SIEM Onboarding Engineer", line: "Explain normalisation to the new hire in one line." },
    "log-src-q3": { name: "Owen Fischer", role: "SIEM Onboarding Engineer", line: "A Windows box with Winlogbeat has been silent for 12 hours. First step?" },
    "log-src-q4": { name: "Owen Fischer", role: "SIEM Onboarding Engineer", line: "Tokyo logs, London analysts. How should we store the time?" },
  },
  briefings: {
    // ── Reading 1: sources and transports ──
    "log-src-r1": [
      {
        kind: "sort",
        title: "How Does It Travel?",
        prompt: "Sources being onboarded at Vantage this month. Pick the transport each one uses.",
        buckets: [
          { id: "udp", label: "Syslog over UDP 514" },
          { id: "tls", label: "Syslog over TLS 6514" },
          { id: "wef", label: "Windows Event Forwarding" },
          { id: "agent", label: "Agent shipping over HTTPS" },
          { id: "api", label: "API pull from the cloud" },
        ],
        items: [
          { id: "a", text: "An old core router that can only send plain syslog", bucket: "udp", why: "Fire and forget: cheap, but lost packets are lost logs and anyone on the path can read them." },
          { id: "b", text: "Linux jump hosts carrying admin session logs, encrypted end to end", bucket: "tls", why: "rsyslog with TLS on 6514: reliable delivery and nobody reads the logs in transit." },
          { id: "c", text: "2,000 Windows desktops pushing Security events to a central collector, no third-party agent allowed", bucket: "wef", why: "WEF is built into Windows: subscriptions push events to a Windows Event Collector." },
          { id: "d", text: "Domain controllers with Winlogbeat installed", bucket: "agent", why: "An agent reads the event channels and ships over HTTPS to the SIEM." },
          { id: "e", text: "Microsoft 365 audit logs", bucket: "api", why: "SaaS doesn't send syslog. The SIEM's connector pulls from the Management Activity API." },
          { id: "f", text: "AWS CloudTrail", bucket: "api", why: "Delivered to S3 and read by the SIEM's connector, not pushed from a device." },
        ],
      },
    ],
    // ── Reading 2: agents and pipelines ──
    "log-src-r2": [
      {
        kind: "pathway",
        title: "Follow the Line to the Index",
        prompt: "vt-jump-02, a Linux jump host, has not shown up in the SIEM since Friday, yet people are using it. Owen wants you to walk one auth.log line from the box to the searchable index, naming what must be true at every hop.",
        goal: "Walk the path a log line takes from vt-jump-02 to the indexer.",
        nodes: [
          { id: "src", label: "auth.log", sub: "vt-jump-02", x: 10, y: 45 },
          { id: "journal", label: "journald", sub: "systemd journal", x: 14, y: 80 },
          { id: "rsyslog", label: "rsyslog forwarder", sub: "60-siem.conf", x: 28, y: 28 },
          { id: "udp", label: "UDP 514 relay", sub: "plain syslog", x: 36, y: 62 },
          { id: "tls", label: "TLS handshake", sub: "CA certificate", x: 46, y: 30 },
          { id: "fw", label: "Edge firewall", sub: "TCP 6514", x: 58, y: 50 },
          { id: "listener", label: "Collector listener", sub: "siem-in", x: 70, y: 25 },
          { id: "parse", label: "Parser pipeline", sub: "grok + schema", x: 80, y: 52 },
          { id: "dlq", label: "Dead-letter queue", sub: "failed parses", x: 68, y: 82 },
          { id: "index", label: "Indexer", sub: "searchable index", x: 90, y: 28 },
        ],
        edges: [
          ["src", "journal"], ["src", "rsyslog"], ["journal", "rsyslog"], ["rsyslog", "udp"], ["rsyslog", "tls"],
          ["udp", "fw"], ["tls", "fw"], ["fw", "listener"], ["listener", "parse"], ["parse", "dlq"], ["parse", "index"], ["dlq", "index"],
        ],
        route: ["src", "rsyslog", "tls", "fw", "listener", "parse", "index"],
        notes: {
          src: "The line exists on disk. That proves nothing about delivery: a source can be busy and invisible at the same time.",
          rsyslog: "The forwarder reads the file and sends everything with *.* @@siem-in.vantage.example:6514. Two @ signs mean TCP; a single @ would be UDP. systemctl can show it running while the forwarding action inside it is suspended.",
          tls: "Before any log leaves, the sender validates the collector's certificate against its CA file. If that CA has expired, the handshake fails, rsyslog logs GnuTLS error -48 and suspends the action. Check the date with openssl x509 -enddate.",
          fw: "The connection must cross the edge on TCP 6514. A block here looks like a timeout on the sender, not a certificate error, so the error text tells you which hop broke.",
          listener: "The collector accepts the stream and stamps the arrival time. Silent sources are found by comparing last-seen time per host against what it should send.",
          parse: "The parser turns free text into fields, such as user.name and source.ip. A line that fails to parse still arrives, but as one unsearchable message.",
          index: "Only here can an analyst search it. A line is useful when it arrives, parses and is indexed with the right clock.",
        },
        traps: {
          journal: "journald is where the line may also be captured, but the SIEM path is rsyslog's forwarding rule. Checking journald tells you the host is logging, not that it is sending.",
          udp: "Nothing in this config sends plain UDP 514. Port 6514 is syslog over TLS; UDP would be unencrypted and unacknowledged, a different design and a different failure.",
          dlq: "The dead-letter queue holds lines that failed parsing on the collector side. This line never reached the collector, so there is nothing for the queue to hold.",
        },
        lesson: "A silent source has one broken hop, and the hop tells you the error. A suspended rsyslog action with a certificate error means TLS and an expired CA; a timeout means the firewall or the route; lines arriving as one blob mean the parser. A service showing as running proves nothing about delivery, so alert on a source going quiet, not only on events.",
      },
    ],
    // ── Reading 3: parsing and normalisation ──
    "log-src-r3": [
      {
        kind: "spotdiff",
        title: "The Parser Update",
        prompt: "Owen shipped a new version of the sshd parser on Friday. Left: the same raw line parsed by version 1.4, which is known good. Right: what version 1.5 produced. Tap the fields where the new parser damaged the data. Some differences are simply a new run.",
        goodTitle: "Parsed by ssh-auth 1.4 (known good)",
        suspectTitle: "Parsed by ssh-auth 1.5",
        good: [
          "@timestamp: 2026-11-04T07:12:44.000Z",
          "event.original: Nov  4 07:12:44 vt-jump-02 sshd[612]: Failed password for oper from 198.51.100.23 port 50211 ssh2",
          "event.ingested: 2026-11-04T07:12:51.220Z",
          "event.dataset: system.auth",
          "event.action: ssh_login",
          "event.outcome: failure",
          "user.name: oper",
          "source.ip: 198.51.100.23",
          "source.port: 50211",
          "host.name: vt-jump-02",
          "process.name: sshd",
          "process.pid: 612",
          "log.file.path: /var/log/auth.log",
          "pipeline.version: ssh-auth 1.4",
        ],
        suspect: [
          "@timestamp: 2026-11-04T08:12:44.000Z",
          "event.original: Nov  4 07:12:44 vt-jump-02 sshd[612]: Failed password for oper from 198.51.100.23 port 50211 ssh2",
          "event.ingested: 2026-11-04T07:12:51.840Z",
          "event.dataset: system.auth",
          "event.action: ssh_login",
          "event.outcome: failure",
          "user.name: oper",
          "source.address: 198.51.100.23",
          "source.port: 22",
          "host.name: vt-jump-02",
          "process.name: sshd",
          "process.pid: 612",
          "log.file.path: /var/log/auth.log",
          "pipeline.version: ssh-auth 1.5",
        ],
        diffs: [
          { line: 0, why: "The event.original says 07:12:44 on a host that logs in UTC, but the new parser stored 08:12:44Z: it applied a one-hour zone offset. Every event from this source now sits an hour in the future and lines up wrongly in any timeline." },
          { line: 7, why: "The value is right but the field is called source.address instead of source.ip. Every rule and search on source.ip silently misses this source: one name for one fact has been broken." },
          { line: 8, why: "source.port says 22 but the original line says port 50211. The pattern captured the server's port instead of the client's. Compare every parsed value with event.original, not just the field names." },
        ],
        decoys: [
          { line: 2, why: "event.ingested is when the pipeline processed the line; it differs on every run and is not part of the log's meaning." },
          { line: 13, why: "The pipeline version is meant to change when the parser is updated. It is the label of the change, not a fault in it." },
        ],
        lesson: "Test a parser by comparing its output with the raw line, field by field: the time (did the zone change it), the field names (do they match the common schema, so one search finds every source) and the values (did the pattern capture the right number). A parser that runs without errors can still be wrong, and a wrong field is quieter than a missing log.",
      },
    ],
    // Drill before the graded CEF line: a LEEF event, field by field.
    "log-src-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a LEEF Event",
        prompt: "CEF's cousin is LEEF, IBM QRadar's format. Same idea: a pipe-delimited header, then key=value attributes. Here's one from Vantage's proxy.",
        source: "LEEF:2.0|Vantage|WebProxy|4.2|BLOCK_URL|^|devTime=Nov 04 2026 08:14:02^src=10.30.4.17^dst=203.0.113.88^dstPort=443^usrName=c.okafor^url=hxxps://login-vantage-support.example/^cat=Phishing^action=blocked",
        fields: [
          { key: "LEEF:2.0", value: "format and version", label: "Format", note: "LEEF 2.0 lets the header name its own delimiter." },
          { key: "Vendor | Product | Version", value: "Vantage | WebProxy | 4.2", label: "Who sent it" },
          { key: "EventID", value: "BLOCK_URL", label: "Event type", note: "The vendor's own event name; the SIEM maps it to a category." },
          { key: "delimiter", value: "^", label: "Attribute separator", note: "Here a caret, not a tab. Parse with the wrong delimiter and every field after the first is lost." },
          { key: "src / dst / dstPort", value: "10.30.4.17 / 203.0.113.88 / 443", label: "Where" },
          { key: "usrName", value: "c.okafor", label: "Who" },
          { key: "url", value: "hxxps://login-vantage-support.example/", label: "What", note: "Defanged with hxxps so nobody clicks it." },
          { key: "cat / action", value: "Phishing / blocked", label: "Verdict" },
        ],
        summary: "Header first, then attributes split by the declared delimiter. Read the graded CEF line the same way: the header to its seventh pipe, then the key=value extension.",
      },
    ],
  },
};
