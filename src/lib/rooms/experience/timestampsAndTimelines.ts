import type { RoomExperience } from "./types";

// "Operation Zero Hour" for the "timestamps-and-timelines" room (rooms-batch-20.ts).
// Script: docs/campaign/09-timestamps-and-timelines.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Varden Shipping (fictional), offices in Tel Aviv, New York and Bengaluru.
// Every conversion in the labs is real (computed). Lab data differs from the
// graded tasks: no 13-digit value from q1 or f1, the queue-order lab is an
// account-takeover chain, not the graded DLP/email/EDR trio (q2), the drill is
// an Okta record, not the graded Falcon ContextTimeStamp (la1), and no lab
// converts the graded Bengaluru logon (ac1).
export const TIMESTAMPS_AND_TIMELINES: RoomExperience = {
  roomId: "timestamps-and-timelines",
  codename: "Operation Zero Hour",
  theme: "time",
  handler: { name: "Ines Moreau", role: "Incident Response Lead, Varden Shipping" },
  briefing: [
    "Varden Shipping. Offices in Tel Aviv, New York and Bengaluru, logs from forty systems.",
    "Every one of them says what time it is. Most of them disagree.",
    "Ines Moreau needs a timeline the board can trust, accurate to the second.",
    "Learn to read every clock, put every event in its true order, and find zero hour.",
  ],
  mission: "Convert every timestamp format, move between UTC and local zones, correct clock skew, rebuild the true order of an attack, and handle the traps that break timelines.",
  estimate: "~50 min",
  look: { primary: "#fbbf24", secondary: "#38bdf8", warn: "#f43f5e" },
  scene: "chrono",
  layout: "stage",
  stations: [
    {
      id: "formats",
      label: "Read the Clock",
      topic: "ISO 8601 · Unix epoch seconds and milliseconds · Windows FILETIME · year-less syslog",
      tagline: "Recognise every timestamp format and convert it on the command line",
      building: "archive",
      taskIds: ["time-r1"],
    },
    {
      id: "zones",
      label: "One Instant, Three Zones",
      topic: "UTC storage, local display · stating the zone · sources that log local time",
      tagline: "The same moment, read in Tel Aviv, New York and Bengaluru",
      building: "control",
      taskIds: ["time-r2", "time-q1", "time-f1"],
    },
    {
      id: "order",
      label: "Fix the Order",
      topic: "Clock skew and NTP · normalise, then sort · detection order vs event order · dwell time",
      tagline: "Three clocks disagree. Correct them and rebuild what really happened first",
      building: "lab",
      taskIds: ["time-r3", "time-r4", "time-q2"],
    },
    {
      id: "instant",
      label: "Same Instant, Two Times",
      topic: "Reading an EDR timestamp next to a local console",
      tagline: "The console and the raw record disagree. Decide who is right",
      building: "ticket",
      taskIds: ["time-la1"],
    },
    {
      id: "traps",
      label: "Zero Hour",
      topic: "DST · year-less logs · duplicate sightings · timestomping and log clearing",
      tagline: "The traps that break timelines, then a 03:50 logon that needs a verdict",
      building: "vault",
      taskIds: ["time-r5", "time-m1", "time-o1", "time-ac1"],
      boss: true,
    },
  ],
  personas: {
    "time-q1": { name: "Ines Moreau", role: "Incident Response Lead", line: "This field is a plain number. Before you convert it, tell me what unit it is in." },
    "time-q2": { name: "Ines Moreau", role: "Incident Response Lead", line: "The alerts came in one order, the events happened in another. What do we do with that?" },
    "time-ac1": { name: "Raj Iyer", role: "IT Lead, Bengaluru office", line: "The SOC flagged a console logon on one of our desks. Can you take a look?" },
  },
  briefings: {
    // ── Reading 1: formats ──
    "time-r1": [
      {
        kind: "sort",
        title: "Name That Timestamp",
        prompt: "All six describe the same instant, in different formats. Name each format.",
        buckets: [
          { id: "iso", label: "ISO 8601" },
          { id: "s", label: "Epoch seconds" },
          { id: "ms", label: "Epoch milliseconds" },
          { id: "ft", label: "Windows FILETIME" },
          { id: "sys", label: "Syslog (no year)" },
        ],
        items: [
          { id: "z", text: "2026-11-04T09:15:30Z", bucket: "iso", why: "Date, a literal T, time, and Z for UTC." },
          { id: "off", text: "2026-11-04T11:15:30+02:00", bucket: "iso", why: "Still ISO 8601, but in a local zone two hours ahead of UTC: the same instant." },
          { id: "sec", text: "1793783730", bucket: "s", why: "10 digits: seconds since 1 January 1970 UTC." },
          { id: "msec", text: "1793783730000", bucket: "ms", why: "13 digits: the same instant in milliseconds. Divide by 1,000 before converting." },
          { id: "ftime", text: "134382573300000000", bucket: "ft", why: "18 digits: 100-nanosecond ticks since 1601." },
          { id: "syslog", text: "Nov  4 09:15:30 fw-tlv-01 kernel: DROP SRC=198.51.100.7", bucket: "sys", why: "Month, day, time, and no year at all." },
        ],
      },
      {
        kind: "terminal",
        title: "Convert Everything",
        prompt: "Analysts convert timestamps on the command line constantly. Turn each raw value into a human date.",
        shell: "bash",
        host: "ines@ir-box:~$",
        commands: [
          { match: "date\\s+-u\\s+-d\\s+@1793783730", help: "date -u -d @<seconds>                         epoch seconds to UTC",
            output: "Wed Nov  4 09:15:30 UTC 2026" },
          { match: "date\\s+-u\\s+-d\\s+@\\$\\(\\(1793783730000\\s*/\\s*1000\\)\\)", help: "date -u -d @$((<milliseconds>/1000))        epoch milliseconds to UTC",
            output: "Wed Nov  4 09:15:30 UTC 2026" },
          { match: "python3\\s+-c\\s+.*1601.*134382573300000000.*", help: "python3 -c \"import datetime as d; print(d.datetime(1601,1,1)+d.timedelta(microseconds=<filetime>//10))\"   FILETIME to UTC",
            output: "2026-11-04 09:15:30" },
          { match: "date\\s+-u", output: "Wed Nov  4 15:02:11 UTC 2026" },
        ],
        objectives: [
          { id: "sec", task: "Convert epoch 1793783730. What is the UTC time of day (HH:MM:SS)?", hint: "date -u -d @1793783730", answer: ["09:15:30"], why: "10 digits, so seconds: 4 November 2026, 09:15:30 UTC." },
          { id: "ms", task: "Convert 1793783730000 the right way. What UTC time of day do you get?", hint: "date -u -d @$((1793783730000/1000))", answer: ["09:15:30"], why: "Divide the 13-digit millisecond value by 1,000 first: the same instant. Skip that step and you land tens of thousands of years in the future." },
          { id: "ft", task: "Convert the FILETIME 134382573300000000. Which date is it (YYYY-MM-DD)?", hint: "python3 -c \"import datetime as d; print(d.datetime(1601,1,1)+d.timedelta(microseconds=134382573300000000//10))\"", answer: ["2026-11-04"], why: "FILETIME counts 100-nanosecond ticks from 1601, so divide by 10 for microseconds and add to 1601-01-01. Same instant again." },
        ],
      },
    ],
    // ── Reading 2: UTC vs local ──
    "time-r2": [
      {
        kind: "terminal",
        title: "One Instant, Three Offices",
        prompt: "An alert fired at 14:20 UTC. Analysts in three offices will each see it in their own time. Work out what each one sees.",
        shell: "bash",
        host: "ines@ir-box:~$",
        commands: [
          { match: "TZ=['\"]?Asia/Jerusalem['\"]?\\s+date\\s+-d\\s+['\"]2026-11-04 14:20 UTC['\"]", help: "TZ='<zone>' date -d '2026-11-04 14:20 UTC'   show a UTC time in a zone",
            output: "Wed Nov  4 16:20:00 IST 2026" },
          { match: "TZ=['\"]?America/New_York['\"]?\\s+date\\s+-d\\s+['\"]2026-11-04 14:20 UTC['\"]",
            output: "Wed Nov  4 09:20:00 EST 2026" },
          { match: "TZ=['\"]?Asia/Kolkata['\"]?\\s+date\\s+-d\\s+['\"]2026-11-04 14:20 UTC['\"]",
            output: "Wed Nov  4 19:50:00 IST 2026" },
          { match: "timedatectl\\s+list-timezones.*", help: "timedatectl list-timezones | grep <city>     find a zone name",
            output: "America/New_York\nAsia/Jerusalem\nAsia/Kolkata" },
        ],
        objectives: [
          { id: "tlv", task: "What does the Tel Aviv analyst's console show (HH:MM)?", hint: "TZ='Asia/Jerusalem' date -d '2026-11-04 14:20 UTC'", answer: ["16:20"], why: "Israel is UTC+2 in November (summer time ended in October)." },
          { id: "nyc", task: "And the New York analyst's (HH:MM)?", hint: "TZ='America/New_York' date -d '2026-11-04 14:20 UTC'", answer: ["09:20"], why: "New York is UTC-5 in November: EST, not the EDT of the summer." },
          { id: "blr", task: "And Bengaluru's (HH:MM)?", hint: "TZ='Asia/Kolkata' date -d '2026-11-04 14:20 UTC'", answer: ["19:50"], why: "India is UTC+5:30 all year. Half-hour offsets catch people out." },
        ],
      },
      {
        kind: "worksheet",
        title: "Which Clock Is It?",
        prompt: "Three people describe the same incident. Turn each statement into UTC before you compare anything.",
        caption: "Statements in the incident channel",
        columns: ["who", "said", "their source"],
        rows: [
          ["New York analyst", "'It started at 09:20'", "SIEM console, set to New York time"],
          ["Tel Aviv firewall admin", "'Our log shows 16:23'", "Branch firewall that logs local time, no zone"],
          ["Bengaluru IT", "'The user called us at 19:58'", "Phone system, India time"],
        ],
        questions: [
          { id: "fw", q: "The firewall's 16:23 is Tel Aviv local time (UTC+2). What is it in UTC (HH:MM)?", hint: "Subtract 2 hours.", answer: ["14:23"], why: "14:23 UTC: three minutes after the alert. A local-time device must be converted before it is compared." },
          { id: "call", q: "The 19:58 phone call is India time (UTC+5:30). In UTC (HH:MM)?", hint: "Subtract 5 hours 30 minutes.", answer: ["14:28"], why: "14:28 UTC: the user called eight minutes after the alert." },
          { id: "first", q: "In UTC, which came first: the alert, the firewall entry or the phone call?", hint: "Compare 14:20, 14:23 and 14:28.", answer: ["alert", "the alert"], why: "Alert 14:20, firewall 14:23, call 14:28. Three people, three clocks, one story, but only once it is all in UTC." },
        ],
      },
    ],
    // ── Readings 3-4: skew, NTP, building the order ──
    "time-r3": [
      {
        kind: "terminal",
        title: "Who's Out of Sync?",
        prompt: "Three systems recorded the same intrusion. Before trusting their times, check each one's clock.",
        shell: "bash",
        host: "ines@ir-box:~$",
        commands: [
          { match: "timedatectl\\s+(status\\s+)?-H\\s+dc01", help: "timedatectl -H <host>                          clock and NTP status of a host",
            output: "               Local time: Wed 2026-11-04 14:30:02 UTC\n           Universal time: Wed 2026-11-04 14:30:02 UTC\n System clock synchronized: yes\n              NTP service: active" },
          { match: "timedatectl\\s+(status\\s+)?-H\\s+edr-relay", output: "               Local time: Wed 2026-11-04 14:28:02 UTC\n           Universal time: Wed 2026-11-04 14:28:02 UTC\n System clock synchronized: no\n              NTP service: inactive\n(reference clock: 14:30:02 UTC)" },
          { match: "timedatectl\\s+(status\\s+)?-H\\s+fw-branch-07", output: "               Local time: Wed 2026-11-04 14:33:02 UTC\n           Universal time: Wed 2026-11-04 14:33:02 UTC\n System clock synchronized: no\n              NTP service: inactive\n(reference clock: 14:30:02 UTC)" },
          { match: "cat\\s+hosts\\.txt", help: "cat hosts.txt                                  the hosts to check", output: "dc01\nedr-relay\nfw-branch-07" },
        ],
        objectives: [
          { id: "ok", task: "Which host's clock is synchronized?", hint: "timedatectl -H dc01 (then the other two)", answer: ["dc01"], why: "NTP active and synchronized: its times can be taken as they are." },
          { id: "fast", task: "fw-branch-07 is out of sync. By how many minutes is it fast?", hint: "timedatectl -H fw-branch-07: compare its time with the reference", answer: ["3", "3 minutes", "three"], why: "14:33 against a true 14:30: three minutes fast. Subtract 3 minutes from every timestamp it logged." },
          { id: "slow", task: "edr-relay is out too. By how many minutes is it slow?", hint: "timedatectl -H edr-relay", answer: ["2", "2 minutes", "two"], why: "14:28 against 14:30: two minutes slow. Add 2 minutes to its timestamps." },
        ],
      },
      {
        kind: "worksheet",
        title: "Correct the Skew",
        prompt: "The same three systems logged the intrusion. Apply the corrections you just measured, then decide the real order.",
        caption: "Raw timestamps, as each system logged them (all UTC)",
        columns: ["system", "clock", "event", "raw time"],
        rows: [
          ["DC01", "in sync", "4624 logon of j.ward from 10.70.4.31", "14:03:55"],
          ["EDR-relay", "2 min slow", "powershell.exe started by j.ward", "14:02:30"],
          ["FW-BRANCH-07", "3 min fast", "10.70.4.31 connects out to 203.0.113.77:443", "14:08:10"],
        ],
        questions: [
          { id: "edr", q: "What is the EDR event's corrected time (HH:MM:SS)?", hint: "Slow by 2 minutes: add 2 minutes.", answer: ["14:04:30"], why: "Raw 14:02:30 looked like the very first event. Corrected, it comes after the logon." },
          { id: "fw", q: "What is the firewall event's corrected time (HH:MM:SS)?", hint: "Fast by 3 minutes: subtract 3 minutes.", answer: ["14:05:10"], why: "Not five minutes after the process, but forty seconds." },
          { id: "first", q: "After correction, which came first: the logon, the PowerShell or the outbound connection?", hint: "Compare 14:03:55, 14:04:30 and 14:05:10.", answer: ["logon", "the logon"], why: "Logon, PowerShell 35 seconds later, outbound connection 40 seconds after that. The raw times told the story backwards." },
        ],
      },
    ],
    "time-r4": [
      {
        kind: "sequence",
        title: "Queue Order Isn't Event Order",
        prompt: "Four alerts reached the queue in the order shown. Each card carries its normalised UTC time. Rebuild the order the events actually happened in.",
        items: [
          { id: "fwd", text: "14:31 UTC · Mailbox forwarding rule created for j.ward", note: "Persistence: mail now copies itself out." },
          { id: "spray", text: "14:02 UTC · Password spray succeeds against j.ward", note: "Initial access: zero hour." },
          { id: "upload", text: "14:45 UTC · 2 GB uploaded to a file-sharing site", note: "Exfiltration." },
          { id: "vpn", text: "14:09 UTC · VPN login for j.ward from a new country", note: "The stolen password in use." },
        ],
        order: ["spray", "vpn", "fwd", "upload"],
        doneNote: "The queue showed persistence first and the spray third; the events say spray, VPN, rule, upload. Dwell time runs from 14:02, not from the first alert you opened.",
      },
    ],
    // Drill before the graded EDR timestamp alert.
    "time-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Timestamped Event",
        prompt: "Your alert compares a raw record with a console display. Ines shows you an identity-provider record first, field by field.",
        source: "Okta System Log · user.session.start",
        fields: [
          { key: "published", value: "2026-11-04T14:20:07.312Z", label: "When", note: "ISO 8601 with a Z: UTC, to the millisecond. This is the value you put in the timeline." },
          { key: "eventType", value: "user.session.start", label: "What happened", note: "A sign-in that created a session." },
          { key: "displayMessage", value: "User login to Okta" },
          { key: "actor.alternateId", value: "j.ward@vardenshipping.example", label: "Who", note: "The user's login name." },
          { key: "client.ipAddress", value: "198.51.100.88", label: "From where", note: "The public IP the sign-in came from." },
          { key: "client.geographicalContext.city", value: "Lisbon", label: "Where, roughly", note: "Geolocation of that IP. Compare it with where the user works: Tel Aviv." },
          { key: "client.geographicalContext.country", value: "Portugal" },
          { key: "outcome.result", value: "SUCCESS", label: "Did it work?", note: "The sign-in succeeded." },
          { key: "securityContext.isProxy", value: "false" },
        ],
        summary: "j.ward signed in from Lisbon at 14:20:07 UTC. A New York analyst's console would show 09:20:07 for the same instant. Write it down with its zone, and it fits any timeline.",
      },
    ],
    // ── Reading 5: the traps ──
    "time-r5": [
      {
        kind: "trace",
        title: "One Logon or Two?",
        prompt: "The timeline shows j.ward logging in twice at 09:00. Two systems, or two logons? Check both logs.",
        lead: "j.ward appears twice around 09:00:00 UTC: once in the VPN log, once on the domain controller.",
        steps: [
          {
            id: "vpn", source: "VPN concentrator log (UTC)",
            ask: "Which VPN session is j.ward's, and which address did it hand out?",
            columns: ["time", "user", "public IP", "assigned IP"],
            rows: [
              ["08:58:41", "a.levi", "203.0.113.20", "10.99.0.14"],
              ["08:59:58", "j.ward", "198.51.100.40", "10.99.0.27"],
              ["09:01:12", "m.cohen", "203.0.113.61", "10.99.0.31"],
            ],
            answer: 1,
            why: "j.ward connected at 08:59:58 and was given 10.99.0.27 inside the VPN pool.",
            learned: "VPN: j.ward at 08:59:58, assigned 10.99.0.27",
          },
          {
            id: "dc", source: "DC01 Security log, 4624 (UTC)",
            ask: "Which logon on the DC is that same VPN session?",
            columns: ["time", "TargetUserName", "LogonType", "IpAddress"],
            rows: [
              ["08:59:30", "j.ward", "3", "10.70.4.31"],
              ["09:00:02", "j.ward", "3", "10.99.0.27"],
              ["09:00:05", "svc_backup", "3", "10.70.1.12"],
            ],
            answer: 1,
            why: "Same user, the VPN-assigned IP, four seconds later: one action seen by two systems. The 08:59:30 logon from 10.70.4.31 is his office desktop, a different session.",
            learned: "DC: the 09:00:02 logon from 10.99.0.27 is the same session",
          },
        ],
      },
      {
        kind: "worksheet",
        title: "The Year Nobody Wrote",
        prompt: "An archived syslog file from a branch firewall. Its lines carry no year. Work it out from the file's metadata.",
        caption: "fw-tlv-01_archive.log · file last modified 2026-01-02 08:10 UTC",
        columns: ["line", "raw entry"],
        rows: [
          ["1", "Dec 31 23:58:12 fw-tlv-01 kernel: DROP SRC=198.51.100.7 DPT=3389"],
          ["2", "Dec 31 23:59:40 fw-tlv-01 kernel: DROP SRC=198.51.100.7 DPT=3389"],
          ["3", "Jan  1 00:03:44 fw-tlv-01 kernel: ACCEPT SRC=198.51.100.7 DPT=443"],
        ],
        questions: [
          { id: "y1", q: "In which year was line 1 written?", hint: "The file was last written on 2 January 2026, so the newest line is from that New Year.", answer: ["2025"], why: "31 December before a file closed in January 2026: 2025. Assuming 'this year' would be off by exactly one year." },
          { id: "y3", q: "And line 3?", hint: "It comes after midnight on New Year.", answer: ["2026"], why: "The year changes between lines 2 and 3. A timeline that guessed one year for the whole file would put line 3 a year before line 1." },
        ],
      },
    ],
  },
};
