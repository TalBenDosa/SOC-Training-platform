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
  scene: "intake",
  layout: "stage",
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
        kind: "terminal",
        title: "Why Did It Go Quiet?",
        prompt: "vt-jump-02, a Linux jump host, hasn't sent a log to the SIEM since Friday. It's up and people are using it. Find out why.",
        shell: "bash",
        host: "owen@vt-jump-02:~$",
        commands: [
          { match: "systemctl\\s+status\\s+rsyslog.*", help: "systemctl status rsyslog --no-pager | head -n 3       is the forwarder running?",
            output: "● rsyslog.service - System Logging Service\n     Loaded: loaded (/lib/systemd/system/rsyslog.service; enabled)\n     Active: active (running) since Mon 2026-10-26 08:00:12 UTC; 1 week 2 days ago" },
          { match: "cat\\s+/etc/rsyslog\\.d/60-siem\\.conf", help: "cat /etc/rsyslog.d/60-siem.conf                        where it forwards to",
            output: "$DefaultNetstreamDriver gtls\n$DefaultNetstreamDriverCAFile /etc/rsyslog.d/certs/siem-ca.pem\n$ActionSendStreamDriverMode 1\n$ActionSendStreamDriverAuthMode x509/name\n*.* @@siem-in.vantage.example:6514" },
          { match: "journalctl\\s+-u\\s+rsyslog.*", help: "journalctl -u rsyslog -n 3 --no-pager                 what rsyslog itself says",
            output: "Nov 04 07:40:02 vt-jump-02 rsyslogd[612]: unexpected GnuTLS error -48 in nsd_gtls.c:1797: Error in the certificate.\nNov 04 07:40:02 vt-jump-02 rsyslogd[612]: netstream session 0x55d3 from siem-in.vantage.example will be closed due to error\nNov 04 07:40:02 vt-jump-02 rsyslogd[612]: action 'action-1-builtin:omfwd' suspended (module 'builtin:omfwd'), retry 0" },
          { match: "openssl\\s+x509\\s+.*-in\\s+/etc/rsyslog\\.d/certs/siem-ca\\.pem.*", help: "openssl x509 -enddate -noout -in /etc/rsyslog.d/certs/siem-ca.pem   when the CA certificate expires",
            output: "notAfter=Oct 30 23:59:59 2026 GMT" },
        ],
        objectives: [
          { id: "port", task: "Which port does it forward to?", hint: "cat /etc/rsyslog.d/60-siem.conf", answer: ["6514"], why: "6514 is syslog over TLS. The @@ means TCP; a single @ would be UDP." },
          { id: "err", task: "What does rsyslog complain about?", hint: "journalctl -u rsyslog -n 3 --no-pager", answer: ["certificate", "the certificate", "certificate error", "tls certificate", "error in the certificate"], why: "The TLS handshake fails, so the forwarding action is suspended. The service still shows 'running'." },
          { id: "why", task: "When did the CA certificate expire?", hint: "openssl x509 -enddate -noout -in /etc/rsyslog.d/certs/siem-ca.pem", answer: ["Oct 30 2026", "Oct 30", "30 Oct 2026", "2026-10-30", "October 30"], why: "Friday 30 October: the day the source went quiet. A 'running' agent isn't proof logs are arriving. Alert on silent sources, not just on events." },
        ],
      },
    ],
    // ── Reading 3: parsing and normalisation ──
    "log-src-r3": [
      {
        kind: "worksheet",
        title: "Five Names, One Schema",
        prompt: "The same kind of facts from five Vantage sources, under their vendor names. Map each to its Elastic Common Schema field, then read the grok pattern that parses the sshd line.",
        caption: "grok for sshd: Failed password for %{USERNAME:user.name} from %{IP:source.ip} port %{NUMBER:source.port} ssh2",
        columns: ["source", "vendor field", "value"],
        rows: [
          ["FortiGate", "srcip", "198.51.100.23"],
          ["Windows 4625", "IpAddress", "198.51.100.23"],
          ["AWS CloudTrail", "sourceIPAddress", "198.51.100.23"],
          ["Okta", "client.ipAddress", "198.51.100.23"],
          ["sshd (raw)", "Failed password for oper from 198.51.100.23 port 50211 ssh2", "(needs grok)"],
        ],
        questions: [
          { id: "ecs", q: "Which ECS field do all four vendor names map to?", hint: "Elastic's name for the source address.", answer: ["source.ip"], why: "One name for one fact: now a single search finds 198.51.100.23 in every source." },
          { id: "user", q: "After the grok pattern runs on the sshd line, what is user.name?", hint: "%{USERNAME:user.name} captures the word after 'for'.", answer: ["oper"], why: "grok turns free text into named fields, directly into the schema's names." },
          { id: "port", q: "And source.port?", hint: "%{NUMBER:source.port}.", answer: ["50211"], why: "Without the parser, this line would be one unsearchable message string." },
        ],
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
