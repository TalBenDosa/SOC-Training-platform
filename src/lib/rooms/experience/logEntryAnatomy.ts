import type { RoomExperience } from "./types";

// "Operation Dissection" for the "log-entry-anatomy" room.
// Script: docs/campaign/10-log-entry-anatomy.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Halvard Energy (fictional). Lab data differs from the graded tasks: the
// syslog bench uses a different host and account than q1's line, the
// key=value lab counts sources rather than asking for the outcome field (q2),
// the severity queue has no scanner-window IPS alert (ac1), and the drill is a
// Zeek http.log record, not the graded conn.log (la1, f1).
export const LOG_ENTRY_ANATOMY: RoomExperience = {
  roomId: "log-entry-anatomy",
  codename: "Operation Dissection",
  theme: "forensics",
  handler: { name: "Felix Adeyemi", role: "Detection Engineer, Halvard Energy" },
  briefing: [
    "Halvard Energy. Two hundred products in the estate, and every one writes its logs its own way.",
    "Nobody memorises them all. Analysts learn to read the ones they have never seen.",
    "Felix Adeyemi puts a raw log on the table and hands you the scalpel: five questions.",
    "When, who, where, what, how sure. Then: what is missing.",
  ],
  mission: "Dissect logs in every format: find the five answers in any entry, slice syslog and key=value with grep and awk, query JSON with jq, read columns by their header, see past vendor names and vendor severity, and tell 'didn't happen' from 'wasn't logged'.",
  estimate: "~55 min",
  look: { primary: "#38bdf8", secondary: "#fbbf24", warn: "#f43f5e" },
  scene: "dissect",
  layout: "stage",
  story: {
    intro: { title: "Two Hundred Formats", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-intro-b63205e0.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-intro-570cfb99.jpg" },
    afterStation: {
      json: { title: "Paths and Columns", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch2-4659f91e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch2-5b5da1bb.jpg" },
      meaning: { title: "Names and Opinions", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch3-25037844.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch3-a1eb5c3f.jpg" },
      absence: { title: "What Isn't There", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-finale-7dc71f96.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-finale-eb080f67.jpg" },
    },
  },
  stations: [
    {
      id: "five",
      label: "The Five Questions",
      topic: "When, who, where, what, how sure: the shape of every log entry",
      tagline: "Pull the five answers out of raw entries you have never seen",
      building: "archive",
      taskIds: ["loganat-r1"],
    },
    {
      id: "text",
      label: "Syslog and Key=Value",
      topic: "RFC 3164 syslog and its priority code · key=value firewall logs · grep and awk",
      tagline: "Slice text logs on the command line the way analysts actually do",
      building: "control",
      taskIds: ["loganat-r2", "loganat-q1", "loganat-r3", "loganat-q2"],
    },
    {
      id: "json",
      label: "Nested JSON",
      topic: "JSON objects, nesting, and what the dots in a field name mean",
      tagline: "Query a Windows event with jq, path by path",
      building: "lab",
      taskIds: ["loganat-r4", "loganat-m1"],
    },
    {
      id: "columns",
      label: "Columns and Headers",
      topic: "CSV and W3C · headerless vendor CSV · CEF and LEEF · a method for any format",
      tagline: "A column means whatever its header says, nothing more",
      building: "office",
      taskIds: ["loganat-r5", "loganat-o1"],
    },
    {
      id: "meaning",
      label: "Names and Opinions",
      topic: "Field naming chaos and normalisation · severity is a vendor opinion",
      tagline: "See past what vendors call things, and how loudly they say them",
      building: "factory",
      taskIds: ["loganat-r6", "loganat-q3", "loganat-r7", "loganat-ac1"],
    },
    {
      id: "absence",
      label: "What Isn't There",
      topic: "Absence of evidence · pipeline gaps · reading a format you've never seen",
      tagline: "A record with no identity, and a silence that might be a gap",
      building: "ticket",
      taskIds: ["loganat-r8", "loganat-la1", "loganat-f1"],
      boss: true,
    },
  ],
  personas: {
    "loganat-q1": { name: "Felix Adeyemi", role: "Detection Engineer", line: "Here's a syslog line from the edge. Apply the frame: who is in it?" },
    "loganat-q2": { name: "Felix Adeyemi", role: "Detection Engineer", line: "FortiGate line. Which field tells you how it ended?" },
    "loganat-q3": { name: "Felix Adeyemi", role: "Detection Engineer", line: "Two products, two names for the same IP. How does one rule catch both?" },
    "loganat-ac1": { name: "Sara Lind", role: "Infrastructure Lead", line: "The DMZ firewall screamed 'critical' overnight. Should I be worried?" },
  },
  briefings: {
    // ── Reading 1: the five questions ──
    "loganat-r1": [
      {
        kind: "worksheet",
        title: "Five Questions, Three Logs",
        prompt: "Three entries from three products you may never have seen. Find the five answers in each.",
        caption: "Raw entries from Halvard Energy",
        columns: ["#", "raw entry"],
        rows: [
          ["A", "2026-11-04T09:12:51Z bastion-01 sshd[2231]: Accepted password for deploy from 198.51.100.23 port 50112 ssh2"],
          ["B", "{\"time\":\"2026-11-04T09:20:11Z\",\"user\":\"deploy\",\"op\":\"CreateUser\",\"target\":\"helpdesk_tmp\",\"result\":\"Success\",\"severity\":\"Medium\"}"],
          ["C", "date=2026-11-04 time=09:24:02 srcip=10.40.6.118 dstip=10.40.2.15 dstport=3389 action=accept level=notice"],
        ],
        questions: [
          { id: "who", q: "Entry A: who logged in (WHO)?", hint: "The account sits inside the free-text message, after 'for'.", answer: ["deploy"], why: "In syslog the identity lives in the sentence, not in a labelled field." },
          { id: "what", q: "Entry B: what was done (WHAT)?", hint: "Look for the operation field.", answer: ["CreateUser", "create user", "createuser"], why: "op=CreateUser, result=Success: the action and its outcome." },
          { id: "where", q: "Entry C: where was the connection going (destination IP)?", hint: "dst means destination.", answer: ["10.40.2.15"], why: "dstip is the target; srcip is where it came from. Mixing them up is the classic mistake." },
          { id: "conf", q: "Entry C: how sure is the vendor that it matters (HOW SURE)?", hint: "The severity word in entry C.", answer: ["notice"], why: "level=notice: the vendor's own, low rating. A login to RDP is still worth context." },
        ],
      },
    ],
    // ── Readings 2-3: syslog and key=value ──
    "loganat-r2": [
      {
        kind: "terminal",
        title: "Slice the Text",
        prompt: "Text logs are read with grep and awk. On the log box, answer the questions straight from the files.",
        shell: "bash",
        host: "felix@logbox:~$",
        commands: [
          { match: "head(\\s+-n?\\s*\\d+)?\\s+raw_udp\\.log", help: "head -n 2 raw_udp.log                     raw syslog as received (with the priority)",
            output: "<38>Nov  4 09:12:51 bastion-01 sshd[2231]: Accepted password for deploy from 198.51.100.23 port 50112 ssh2\n<86>Nov  4 09:12:51 bastion-01 sshd[2231]: pam_unix(sshd:session): session opened for user deploy" },
          { match: "grep\\s+['\"]?Failed password['\"]?\\s+auth\\.log.*", help: "grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn   failures per source IP",
            output: "     41 198.51.100.23\n      6 203.0.113.80\n      1 10.40.6.12" },
          { match: "grep\\s+['\"]?Accepted['\"]?\\s+auth\\.log.*", help: "grep 'Accepted' auth.log                   successful logins",
            output: "Nov  4 08:02:14 bastion-01 sshd[1180]: Accepted publickey for ops from 10.40.6.12 port 41220 ssh2\nNov  4 09:12:51 bastion-01 sshd[2231]: Accepted password for deploy from 198.51.100.23 port 50112 ssh2" },
        ],
        objectives: [
          { id: "top", task: "Which source IP failed the most SSH passwords?", hint: "grep 'Failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn", answer: ["198.51.100.23"], why: "41 failures from one address: password guessing. awk picked the IP out of the free text by its position from the end." },
          { id: "in", task: "Did that IP get in? Which account accepted its password?", hint: "grep 'Accepted' auth.log", answer: ["deploy"], why: "After 41 failures, 'Accepted password for deploy' from the same IP. The guessing worked: this is now an incident." },
          { id: "sev", task: "The raw line starts <38>. Priority = facility x 8 + severity. What is the severity number?", hint: "38 = 4 x 8 + ?", answer: ["6"], why: "38 = 4 x 8 + 6: facility 4 (auth), severity 6 (informational). The protocol's own severity, unrelated to any SIEM score." },
        ],
      },
    ],
    "loganat-r3": [
      {
        kind: "terminal",
        title: "Key=Value at Scale",
        prompt: "The edge FortiGate writes key=value. Every field is labelled, so pulling one out of thousands of lines is one grep.",
        shell: "bash",
        host: "felix@logbox:~$",
        commands: [
          { match: "head(\\s+-n?\\s*\\d+)?\\s+fortigate\\.log", help: "head -n 2 fortigate.log                  what a line looks like",
            output: "date=2026-11-04 time=09:14:22 devname=\"FG100F-EDGE\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=203.0.113.80 srcport=51022 dstip=10.40.9.4 dstport=22 proto=6 action=\"deny\" policyid=3\ndate=2026-11-04 time=09:14:25 devname=\"FG100F-EDGE\" type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=10.40.8.21 srcport=55120 dstip=203.0.113.140 dstport=443 proto=6 action=\"accept\" policyid=12" },
          { match: "grep\\s+.*deny.*fortigate\\.log.*(srcip|uniq).*", help: "grep 'action=\"deny\"' fortigate.log | grep -o 'srcip=[0-9.]*' | sort | uniq -c | sort -rn   denied sources",
            output: "    214 srcip=203.0.113.80\n     37 srcip=198.51.100.23\n      2 srcip=10.40.6.40" },
          { match: "grep\\s+.*dstport=22.*fortigate\\.log.*", help: "grep 'dstport=22 ' fortigate.log | wc -l   connections to SSH",
            output: "251" },
        ],
        objectives: [
          { id: "deny", task: "Which source was denied most often?", hint: "grep 'action=\"deny\"' fortigate.log | grep -o 'srcip=[0-9.]*' | sort | uniq -c | sort -rn", answer: ["203.0.113.80"], why: "214 denies. Because srcip is labelled, grep -o pulls it out of any line without knowing where in the line it sits." },
          { id: "dir", task: "In the first line, is 10.40.9.4 the source or the destination?", hint: "head -n 2 fortigate.log, then read which key it sits under", answer: ["destination", "dst", "dstip"], why: "It is dstip: the internal host being targeted. Always read the key before trusting your instinct about direction." },
        ],
      },
    ],
    // ── Reading 4: JSON ──
    "loganat-r4": [
      {
        kind: "terminal",
        title: "Query JSON with jq",
        prompt: "A Windows Security event exported as JSON. Use jq to walk the nested path to each answer.",
        shell: "bash",
        host: "felix@logbox:~$",
        commands: [
          { match: "cat\\s+event\\.json", help: "cat event.json                            the whole event",
            output: "{\n  \"@timestamp\": \"2026-11-04T09:20:11.000Z\",\n  \"host\": { \"name\": \"DC02\" },\n  \"winlog\": {\n    \"channel\": \"Security\",\n    \"event_id\": 4720,\n    \"computer_name\": \"DC02.halvard.local\",\n    \"event_data\": {\n      \"SubjectUserName\": \"deploy\",\n      \"SubjectDomainName\": \"HALVARD\",\n      \"TargetUserName\": \"helpdesk_tmp\",\n      \"TargetDomainName\": \"HALVARD\"\n    }\n  }\n}" },
          { match: "jq\\s+(-r\\s+)?['\"]?\\.winlog\\.event_id['\"]?\\s+event\\.json", help: "jq '.winlog.event_id' event.json         read one nested field", output: "4720" },
          { match: "jq\\s+(-r\\s+)?['\"]?\\.winlog\\.event_data\\.TargetUserName['\"]?\\s+event\\.json", output: "helpdesk_tmp" },
          { match: "jq\\s+(-r\\s+)?['\"]?\\.winlog\\.event_data\\.SubjectUserName['\"]?\\s+event\\.json", output: "deploy" },
          { match: "jq\\s+(-r\\s+)?['\"]?\\.winlog\\.event_data['\"]?\\s+event\\.json", output: "{\n  \"SubjectUserName\": \"deploy\",\n  \"SubjectDomainName\": \"HALVARD\",\n  \"TargetUserName\": \"helpdesk_tmp\",\n  \"TargetDomainName\": \"HALVARD\"\n}" },
          { match: "jq\\s+.*", output: "null\n(no such path: walk it from the top, for example .winlog.event_data)" },
        ],
        objectives: [
          { id: "id", task: "What is the Windows event ID?", hint: "jq '.winlog.event_id' event.json", answer: ["4720"], why: "4720: a user account was created." },
          { id: "new", task: "Which account was created?", hint: "jq '.winlog.event_data.TargetUserName' event.json", answer: ["helpdesk_tmp"], why: "Target is the object of the action: the new account." },
          { id: "by", task: "Which account created it?", hint: "jq '.winlog.event_data.SubjectUserName' event.json", answer: ["deploy"], why: "Subject is the actor. The same deploy account that just brute-forced its way in over SSH." },
          { id: "path", task: "Write the full dotted path of the field that holds the new account's name.", hint: "The path you gave jq, without the leading dot.", answer: ["winlog.event_data.TargetUserName", ".winlog.event_data.TargetUserName"], why: "In a SIEM's field list this appears as winlog.event_data.TargetUserName: the dots are the path through the nesting." },
        ],
      },
    ],
    // ── Reading 5: CSV/W3C, headerless CSV, CEF/LEEF ──
    "loganat-r5": [
      {
        kind: "worksheet",
        title: "Read It by the Header",
        prompt: "This IIS log uses a non-default column order. Read every value by its header, never by habit.",
        caption: "u_ex261104.log · IIS W3C extended log",
        columns: ["line", "content"],
        rows: [
          ["header", "#Fields: time cs-method cs-uri-stem sc-status c-ip cs-username"],
          ["1", "09:01:12 GET /portal/login 200 10.40.8.21 -"],
          ["2", "09:01:40 POST /portal/login 401 198.51.100.23 admin"],
          ["3", "09:02:03 POST /portal/login 200 198.51.100.23 m.okafor"],
        ],
        questions: [
          { id: "status", q: "What status did line 2's login get?", hint: "Status is the 4th column here (sc-status).", answer: ["401"], why: "401: unauthorised. In the default IIS layout the 4th value would be something else entirely." },
          { id: "ip", q: "Which client IP made the successful POST on line 3?", hint: "c-ip is the 5th column in this header.", answer: ["198.51.100.23"], why: "The same address that failed as 'admin' 23 seconds earlier." },
          { id: "user", q: "Which account logged in successfully on line 3?", hint: "cs-username is the last column.", answer: ["m.okafor"], why: "A failed guess, then a successful login as a real user from the same IP: credential stuffing that worked." },
        ],
      },
      {
        kind: "worksheet",
        title: "No Header at All",
        prompt: "Palo Alto's native syslog is a comma-separated line with no names. Only the vendor's field-order table tells you what each position means.",
        caption: "PAN-OS TRAFFIC log line + the vendor's field-order table (first 15 positions)",
        columns: ["position", "field (from the vendor table)", "value in this line"],
        rows: [
          ["1", "FUTURE_USE", "1"], ["2", "Receive Time", "2026/11/04 09:05:44"], ["3", "Serial Number", "015701002342"], ["4", "Type", "TRAFFIC"],
          ["5", "Threat/Content Type", "end"], ["6", "FUTURE_USE", "2561"], ["7", "Generated Time", "2026/11/04 09:05:44"], ["8", "Source Address", "?"],
          ["9", "Destination Address", "?"], ["10", "NAT Source IP", "198.51.100.5"], ["11", "NAT Destination IP", "203.0.113.140"], ["12", "Rule Name", "?"],
          ["13", "Source User", "halvard\\m.okafor"], ["14", "Destination User", "(empty)"], ["15", "Application", "?"],
        ],
        questions: [
          { id: "src", q: "The raw line is: 1,2026/11/04 09:05:44,015701002342,TRAFFIC,end,2561,2026/11/04 09:05:44,10.40.8.21,203.0.113.140,198.51.100.5,203.0.113.140,allow-web,halvard\\m.okafor,,ssl. What is the source address (position 8)?", hint: "Count the commas: position 8 is the 8th value.", answer: ["10.40.8.21"], why: "Nothing in the line says 'source': only the vendor's table does. And that table can change between versions." },
          { id: "rule", q: "Which rule allowed the session (position 12)?", hint: "The 12th value.", answer: ["allow-web"], why: "Rule Name sits right after the two NAT addresses." },
          { id: "app", q: "Which application was it (position 15)?", hint: "The 15th value; position 14 is empty (two commas in a row).", answer: ["ssl"], why: "An empty value still takes a position. Miscount one comma and every field after it is wrong." },
        ],
      },
    ],
    // ── Readings 6-7: names and severity ──
    "loganat-r6": [
      {
        kind: "match",
        title: "One Fact, Five Names",
        prompt: "The same source IP, as five products name it. Match each field name to the product that uses it.",
        pairs: [
          { id: "fg", left: "srcip", right: "Fortinet FortiGate traffic log", why: "Fortinet's key=value name." },
          { id: "zeek", left: "id.orig_h", right: "Zeek conn.log", why: "Zeek: the originator's host." },
          { id: "iis", left: "c-ip", right: "IIS W3C log", why: "Client IP, in IIS's column naming." },
          { id: "entra", left: "ClientIP / IPAddress", right: "Entra ID sign-in log", why: "Microsoft's identity logs." },
          { id: "ecs", left: "source.ip", right: "Elastic Common Schema, after normalisation", why: "The one name a SIEM search uses for all of them." },
        ],
      },
    ],
    "loganat-r7": [
      {
        kind: "queue",
        title: "Severity Is an Opinion",
        prompt: "Four alerts, four vendor severities. Ignore the label for a moment and read what actually happened.",
        console: "SIEM · alert queue · Halvard Energy",
        actions: [
          { id: "now", label: "Investigate now", tone: "escalate" },
          { id: "routine", label: "Routine review", tone: "close" },
        ],
        alerts: [
          { id: "lockbit", time: "01:40", severity: "Critical", rule: "Ransomware family detected", entity: "FS-ARCHIVE",
            fields: [{ k: "file", v: "backup_2019\\old_tools.zip > loader.exe" }, { k: "action", v: "Quarantined on scan" }, { k: "executed", v: "never" }, { k: "trigger", v: "weekly archive scan" }],
            context: "A seven-year-old archive was scanned; the file was quarantined before anything ran.", answer: "routine", why: "Critical by family, harmless here: never executed, already quarantined. Note it and clean the archive." },
          { id: "lockout", time: "03:12", severity: "Medium", rule: "Account locked out (4740)", entity: "DC02 · Administrator",
            fields: [{ k: "account", v: "Administrator" }, { k: "caller", v: "WS-0233" }, { k: "maintenance", v: "none scheduled" }],
            context: "The built-in Administrator account was locked out by failed attempts from a workstation at 3 a.m.", answer: "now", why: "Only 'medium', but someone is guessing the domain's most powerful account at night. Investigate now." },
          { id: "dagroup", time: "02:47", severity: "Low", rule: "Member added to security group (4728)", entity: "Domain Admins",
            fields: [{ k: "group", v: "Domain Admins" }, { k: "member added", v: "helpdesk_tmp" }, { k: "by", v: "deploy" }],
            context: "A brand-new account was added to Domain Admins by a CI service account.", answer: "now", why: "'Low' because group changes are common. This one hands full domain control to an account created an hour ago." },
          { id: "cert", time: "08:00", severity: "High", rule: "TLS certificate expires in 3 days", entity: "intranet.halvard.local",
            fields: [{ k: "expires", v: "2026-11-07" }, { k: "owner", v: "Web team" }],
            context: "A certificate is about to expire.", answer: "routine", why: "Vendor 'high', but an operations ticket, not a security incident. Route it to the web team." },
        ],
      },
    ],
    // ── Reading 8: absence of evidence ──
    "loganat-r8": [
      {
        kind: "trace",
        title: "Silence or Gap?",
        prompt: "A workstation shows a logon at 03:11, but the domain controller shows nothing. Did it not happen, or was it not delivered?",
        lead: "WS-0233 logged a successful logon for helpdesk_tmp at 03:11. Searching DC02 for it in the SIEM returns nothing.",
        steps: [
          {
            id: "ws", source: "WS-0233 local Security log",
            ask: "Which entry is the successful logon?",
            columns: ["time (UTC)", "EventID", "account", "result"],
            rows: [["03:10:12", "4625", "helpdesk_tmp", "failure"], ["03:10:40", "4625", "helpdesk_tmp", "failure"], ["03:11:05", "4624", "helpdesk_tmp", "success"]],
            answer: 2,
            why: "4624 at 03:11:05. A domain logon like this should also leave a trace on the DC.",
            learned: "WS-0233: helpdesk_tmp logged on at 03:11:05",
          },
          {
            id: "siem", source: "SIEM · all DC02 events, 02:50-03:50",
            ask: "Where does DC02's stream of events stop?",
            columns: ["time (UTC)", "EventID", "summary"],
            rows: [["02:53:41", "4624", "svc_backup network logon"], ["02:54:58", "4768", "Kerberos TGT for ops"], ["03:41:10", "4624", "svc_backup network logon"], ["03:41:12", "4672", "special privileges assigned"]],
            answer: 1,
            why: "Nothing between 02:54:58 and 03:41:10 on a domain controller that normally logs every few seconds. Forty-six minutes of silence is not normal.",
            learned: "DC02 went silent in the SIEM from 02:55 to 03:41",
          },
          {
            id: "fwd", source: "Log forwarder heartbeats",
            ask: "Which forwarder explains the silence?",
            columns: ["host", "agent", "last heartbeat", "status"],
            rows: [["DC01", "winlogbeat 8.15", "03:49:58", "running"], ["DC02", "winlogbeat 8.15", "02:55:03", "stopped"], ["FS-ARCHIVE", "winlogbeat 8.15", "03:49:57", "running"]],
            answer: 1,
            why: "DC02's forwarder stopped at 02:55 and came back at 03:41. The events were never delivered: 'no evidence' here means 'not logged', not 'didn't happen'.",
            learned: "Cause: DC02's forwarder was stopped 02:55 to 03:41: a pipeline gap",
          },
        ],
      },
    ],
    // Drill before the graded Zeek record: a different Zeek log, decoded.
    "loganat-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Zeek HTTP Record",
        prompt: "Your alert is a Zeek record in a format you haven't seen. Felix shows you another Zeek log first: http.log, field by field.",
        source: "Zeek · http.log · core-VLAN sensor",
        fields: [
          { key: "ts", value: "1793781902.144", label: "When", note: "Epoch seconds with a fraction: 10 digits before the point." },
          { key: "uid", value: "C8sPzK3vTq9fLm2Wd1", label: "Session ID", note: "Zeek's own ID for this connection. The same uid links this record to its conn.log entry." },
          { key: "id.orig_h", value: "10.40.6.118", label: "Where from", note: "The originator: the host that opened the connection." },
          { key: "id.resp_h", value: "203.0.113.140", label: "Where to", note: "The responder: the server." },
          { key: "id.resp_p", value: "80" },
          { key: "method", value: "GET", label: "What", note: "The HTTP method: here, fetching something." },
          { key: "host", value: "updates.halvard-it.example", label: "Which site", note: "The Host header. Compare it with the company's real update servers." },
          { key: "uri", value: "/agent/v2/check", label: "Which path", note: "Plain HTTP, so the path is visible." },
          { key: "user_agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
          { key: "status_code", value: "200", label: "Result", note: "200: the server answered successfully." },
          { key: "resp_mime_types", value: "[\"application/x-dosexec\"]", label: "What came back", note: "Zeek sniffed the response body: a Windows executable, not a web page." },
          { key: "response_body_len", value: "524288" },
        ],
        summary: "At this moment 10.40.6.118 fetched a Windows executable over plain HTTP from updates.halvard-it.example. Answer the five questions you can, and note the ones this format cannot answer at all.",
      },
    ],
  },
};
