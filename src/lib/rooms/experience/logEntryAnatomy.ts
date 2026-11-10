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
  mission: "Dissect logs in every format: find the five answers in any entry, slice syslog by position and key=value by label, follow nested JSON paths, read columns by their header, see past vendor names and vendor severity, and tell 'didn't happen' from 'wasn't logged'.",
  estimate: "~55 min",
  look: { primary: "#38bdf8", secondary: "#fbbf24", warn: "#f43f5e" },
  scene: "facilitylogentryanatomy",
  layout: "facility",
  story: {
    intro: { title: "Two Hundred Formats", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-intro-a5b2656d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-intro-21749cfd.jpg" },
    afterStation: {
      json: { title: "Paths and Columns", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch2-aa9042de.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch2-08b86aee.jpg" },
      meaning: { title: "Names and Opinions", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch3-76123c69.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-ch3-45e95496.jpg" },
      absence: { title: "What Isn't There", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-finale-4daf58eb.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/log-entry-anatomy/dissection-finale-513b7d1c.jpg" },
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
      tagline: "Slice text logs field by field the way analysts actually do",
      building: "control",
      taskIds: ["loganat-r2", "loganat-q1", "loganat-r3", "loganat-q2"],
    },
    {
      id: "json",
      label: "Nested JSON",
      topic: "JSON objects, nesting, and what the dots in a field name mean",
      tagline: "Follow a Windows event path by path",
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
        kind: "codebreak",
        title: "Crack the Field Name",
        prompt: "Felix covers the labels on four log fragments and leaves you a clue for each. Name the field, the keyword or the tool before the stack of raw lines buries you.",
        tries: 6,
        rounds: [
          { id: "pri", clue: "A raw syslog line starts with <27>. That priority is facility x 8 + severity, and 27 has facility 3 (daemon). Which three-letter severity keyword is left over?", answer: "err", why: "27 - 24 = 3, and severity 3 is err. This is the protocol's own severity, unrelated to any score a SIEM assigns." },
          { id: "dst", clue: "A FortiGate key=value line labels both ends of the connection. Which five-letter key names the address the traffic was heading to?", answer: "dstip", why: "dstip is the destination, srcip the origin. Mixing them up flips who attacked whom, so read the key before trusting your instinct." },
          { id: "awk", clue: "Syslog has no labels: the account sits in the sentence after the word for. Which three-letter command-line tool prints the Nth word of each line, as in print $(NF-5)?", answer: "awk", why: "awk picks a field by its position, here counted from the end of the line. It works on free text, but only as long as the sentence keeps its shape." },
          { id: "dpt", clue: "In CEF, a pipe-delimited header is followed by short keys. Which three-letter key holds the destination port?", answer: "dpt", why: "CEF abbreviates: src, dst, dpt, act. Each product defines its own short names, so the key tells you nothing until you read the product's map." },
        ],
        lesson: "A labelled field is read by its key, an unlabelled one by its position, and each format has its own names for the same fact. Find the label first, then the value.",
      },
    ],
    "loganat-r3": [
      {
        kind: "spotdiff",
        title: "Forged Firewall Lines",
        prompt: "Someone pasted firewall lines into a ticket and Felix suspects they were edited. Compare against the central copy and tap every line whose facts were changed.",
        goodTitle: "Central copy (as written)",
        suspectTitle: "Copy attached to the ticket",
        good: [
          "time=09:14:22 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:25 srcip=10.40.8.21 dstip=203.0.113.140 dstport=443 action=\"accept\" level=\"notice\"",
          "time=09:14:31 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:33 srcip=10.40.8.30 dstip=10.40.0.10 dstport=53 action=\"accept\" level=\"notice\"",
          "time=09:14:40 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:44 srcip=10.40.6.40 dstip=203.0.113.140 dstport=443 action=\"accept\" level=\"notice\"",
          "time=09:14:52 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:58 srcip=10.40.9.4 dstip=203.0.113.140 dstport=8443 action=\"accept\" level=\"notice\"",
          "time=09:15:10 srcip=10.40.8.21 dstip=10.40.0.10 dstport=53 action=\"accept\" level=\"notice\"",
          "time=09:15:15 srcip=10.40.7.12 dstip=203.0.113.140 dstport=443 action=\"accept\" level=\"notice\"",
          "time=09:15:20 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"accept\" level=\"notice\"",
          "time=09:15:31 srcip=10.40.8.30 dstip=10.40.0.10 dstport=53 action=\"accept\" level=\"notice\"",
        ],
        suspect: [
          "time=09:14:22 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:25 srcip=10.40.8.21 dstip=203.0.113.140 dstport=443 action=\"accept\" level=\"notice\"",
          "time=09:14:31 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:33 srcip=10.40.8.30 dstip=10.40.0.10 dstport=53 action=\"accept\" level=\"notice\"",
          "time=09:14:40 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:44 srcip=10.40.6.40 dstip=203.0.113.140 dstport=443 action=\"accept\" level=\"notice\"",
          "time=09:14:52 srcip=203.0.113.80 dstip=10.40.9.4 dstport=22 action=\"deny\" level=\"notice\"",
          "time=09:14:58 srcip=10.40.9.4 dstip=10.40.0.10 dstport=8443 action=\"accept\" level=\"notice\"",
          "time=09:15:10 srcip=10.40.8.21 dstip=10.40.0.10 dstport=53 action=\"accept\" level=\"notice\"",
          "time=09:05:15 srcip=10.40.7.12 dstip=203.0.113.140 dstport=443 action=\"accept\" level=\"notice\"",
          "time=09:15:20 srcip=10.40.6.40 dstip=10.40.9.4 dstport=22 action=\"accept\" level=\"notice\"",
          "time=09:15:31 srcip=10.40.8.30 dstip=10.40.0.10 dstport=53 action=\"accept\" level=\"warning\"",
        ],
        diffs: [
          { line: 7, why: "The web server's outbound connection on 8443 now points at an internal DNS address. The original dstip was an outside host, and swapping one value turns a callout into housekeeping." },
          { line: 9, why: "The time moved from 09:15:15 to 09:05:15. In a log written in order, a line that sorts ten minutes early breaks the sequence and moves the event out of the window being investigated." },
          { line: 10, why: "The srcip of the accepted SSH connection changed from the outside address to an internal workstation, which blames the wrong machine. Source and destination are the facts a ticket must not alter." },
        ],
        decoys: [
          { line: 11, why: "Only level changed, from notice to warning. Level is the vendor's own opinion of the line, and a re-export can relabel it without altering who connected to what." },
        ],
        lesson: "Forged lines change facts: who, where to, and when. Compare srcip, dstip and the clock against the central copy, and treat severity labels as opinion.",
      },
    ],
    // ── Reading 4: JSON ──
    "loganat-r4": [
      {
        kind: "rush",
        title: "Field Meaning Blitz",
        prompt: "Felix hands you event after event from Halvard's estate. Before the JSON is parsed, call what each field really means: true or false.",
        seconds: 60,
        target: 10,
        cards: [
          { id: "f1", text: "In a Windows 4720 event, TargetUserName is the account that was created.", answer: true, why: "Target is the object of the action, which here is the new account." },
          { id: "f2", text: "In a 4720 event, SubjectUserName is the account that was created.", answer: false, why: "Subject is the actor, the account that did the creating. Swapping actor and object blames the wrong person." },
          { id: "f3", text: "winlog.event_data.TargetUserName means: winlog contains event_data, which contains TargetUserName.", answer: true, why: "In a SIEM field list the dots are the path through the nesting, read from the top." },
          { id: "f4", text: "A dot in a field name always means the JSON is nested.", answer: false, why: "Some tools write flat keys that contain dots, like id.orig_h. Check the structure before you write the path." },
          { id: "f5", text: "If you misspell one level of a field path, the search finds nothing instead of raising an error.", answer: true, why: "A missing key is simply absent, so a null answer usually means a wrong path, not an empty event." },
          { id: "f6", text: "The text \"4624\" in quotes and the number 4624 are the same to every search.", answer: false, why: "One is a string and the other a number. Some queries and indexes treat them differently, so a rule can miss one." },
          { id: "f7", text: "In key=value logs every field is labelled, so grep can pull srcip wherever it sits.", answer: true, why: "The label travels with the value. That is the big advantage over free-text syslog." },
          { id: "f8", text: "In a headerless vendor CSV you can name each column from the first line alone.", answer: false, why: "With no header, only the vendor's field-order table says what position 8 means. Miscount a comma and everything after is wrong." },
          { id: "f9", text: "srcip, id.orig_h and c-ip are three different facts.", answer: false, why: "Three products' names for the same fact: where the connection came from. Normalisation exists to join them." },
          { id: "f10", text: "In ECS, source.ip is the one name a SIEM maps those source addresses to.", answer: true, why: "After normalisation one search on source.ip covers every product." },
          { id: "f11", text: "A vendor severity of Critical proves the event is a confirmed incident.", answer: false, why: "Severity is the vendor's opinion. A critical label can sit on a file that never ran." },
          { id: "f12", text: "A low vendor severity can still hide an event that needs action now.", answer: true, why: "Adding a new account to Domain Admins can be rated Low because group changes are common. Read what happened." },
          { id: "f13", text: "In a PAN-OS style CSV line, an empty value still occupies a position.", answer: true, why: "Two commas in a row mean an empty field, and the count must not slip." },
          { id: "f14", text: "A quiet log proves the event never happened.", answer: false, why: "It may only mean it was not logged or not delivered. Check the pipeline before you call silence an alibi." },
        ],
        lesson: "Names differ by vendor, but every field answers one of the five questions. Read the label, the nesting and the actor-versus-object role, and treat vendor severity as an opinion.",
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
            id: "siem", source: "SIEM · DC02 events around 03:11, excerpt 02:53-03:42",
            ask: "Where does DC02's stream of events stop?",
            columns: ["time (UTC)", "EventID", "summary"],
            rows: [["02:53:41", "4624", "svc_backup network logon"], ["02:54:58", "4768", "Kerberos TGT for ops"], ["03:41:10", "4624", "svc_backup network logon"], ["03:41:12", "4672", "special privileges assigned"]],
            answer: 1,
            why: "Nothing between 02:54:58 and 03:41:10 on a domain controller that normally logs every few seconds. Forty-six minutes of silence is not normal.",
            learned: "DC02 went silent in the SIEM from 02:55 to 03:41",
          },
          {
            id: "fwd", source: "Log forwarder status changes · 01:00-04:00",
            ask: "Which forwarder explains the silence?",
            columns: ["time (UTC)", "host", "agent", "status"],
            rows: [["01:17:22", "FS-ARCHIVE", "winlogbeat 8.15", "restarted (config reload)"], ["02:55:03", "DC02", "winlogbeat 8.15", "stopped"], ["03:41:08", "DC02", "winlogbeat 8.15", "started"], ["03:44:51", "DC01", "winlogbeat 8.15", "restarted (config reload)"]],
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
