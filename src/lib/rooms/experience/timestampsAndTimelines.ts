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
  story: {
    intro: { title: "Forty Clocks", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-intro-f50c26b2.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-intro-bdd863f3.jpg" },
    afterStation: {
      order: { title: "Three Clocks Disagree", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-ch2-6d589897.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-ch2-678cf26f.jpg" },
      instant: { title: "Same Instant", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-ch3-b9102c15.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-ch3-41d422c0.jpg" },
      traps: { title: "Zero Hour", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-finale-e6959544.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/timestamps-and-timelines/zero-hour-finale-8d3d685f.jpg" },
    },
  },
  stations: [
    {
      id: "formats",
      label: "Read the Clock",
      topic: "ISO 8601 · Unix epoch seconds and milliseconds · Windows FILETIME · year-less syslog",
      tagline: "Recognise every timestamp format and convert it against the clock",
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
        kind: "defuse",
        title: "Defuse the Raw Value",
        prompt: "Ines is building the board timeline and four raw values refuse to read as dates. Each one is wired to a single right conversion. Cut it before the clock runs out.",
        device: "Timestamp converter",
        seconds: 80,
        rounds: [
          { id: "ms", state: "A SaaS audit export shows the value 1793790840000. Read as seconds, it lands tens of thousands of years in the future.", wires: [{ id: "a", label: "Read it as epoch seconds as it is" }, { id: "b", label: "Divide by 1,000, then read as epoch seconds" }, { id: "c", label: "Read it as FILETIME" }], cut: "b", hint: "Count the digits.", why: "Thirteen digits is epoch milliseconds. Divide by 1,000 and you get a ten-digit seconds value; skipping that step is how timelines end up tens of thousands of years in the future." },
          { id: "ft", state: "A Defender record carries 134382600000000000, an 18-digit value, in a field called Timestamp.", wires: [{ id: "a", label: "Divide by 1,000, then read as epoch seconds" }, { id: "b", label: "Read it as 100-nanosecond ticks since 1601 (FILETIME)" }, { id: "c", label: "Read it as epoch seconds as it is" }], cut: "b", hint: "Eighteen digits is a lot of zeros.", why: "FILETIME counts 100-nanosecond ticks from 1601-01-01. Divide by 10 for microseconds, add to 1601, and you get the true instant; the 1970 epoch methods would put it centuries away." },
          { id: "iso", state: "A Tel Aviv proxy logs 2026-11-04T11:15:30+02:00, but the SIEM column you are filling is UTC.", wires: [{ id: "a", label: "Add 2 hours to get UTC" }, { id: "b", label: "Copy it as is, because the T means it is UTC" }, { id: "c", label: "Subtract 2 hours to get UTC" }], cut: "c", hint: "A plus offset means the local clock is ahead of UTC.", why: "+02:00 says local time is two hours ahead of UTC, so UTC is 09:15:30. Only a Z at the end, or +00:00, means the value is already UTC." },
          { id: "sys", state: "A branch firewall writes Nov  4 23:58:12 fw-tlv-01 kernel: DROP in an archive. No year, no zone.", wires: [{ id: "a", label: "Assume this year and treat it as UTC" }, { id: "b", label: "Use the SIEM ingest time as the event time" }, { id: "c", label: "Check the device's timezone setting and the file's last-modified date" }], cut: "c", hint: "The line itself holds neither answer.", why: "Syslog omits the year and the zone, so both must come from outside: the device's configured zone, and the file's modified date to pick the year. Ingest time is when it arrived, not when it happened." },
        ],
        lesson: "Count the digits and read the suffix. Ten digits are seconds, thirteen are milliseconds, eighteen are FILETIME, a Z is UTC, a plus or minus offset must be converted, and syslog needs a zone and a year from outside the line.",
      },
    ],
    // ── Reading 2: UTC vs local ──
    "time-r2": [
      {
        kind: "rush",
        title: "One Instant, Three Offices",
        prompt: "An alert fired at 14:20 UTC on 4 November. Tel Aviv, New York and Bengaluru will each read it in their own time, and Ines wants the offsets in your fingers. True or false, fast.",
        seconds: 60,
        target: 10,
        cards: [
          { id: "o1", text: "14:20 UTC is 16:20 in Tel Aviv in early November.", answer: true, why: "Israel is UTC+2 once summer time ends in late October, so add two hours." },
          { id: "o2", text: "14:20 UTC is 10:20 in New York on 4 November.", answer: false, why: "New York is on EST, UTC-5, so it is 09:20. UTC-4 is the summer EDT offset." },
          { id: "o3", text: "14:20 UTC is 19:50 in Bengaluru.", answer: true, why: "India is UTC+5:30: five hours and thirty minutes added to 14:20." },
          { id: "o4", text: "14:20 UTC is 19:20 in Bengaluru.", answer: false, why: "That adds only five hours. India's offset has an extra half hour, which is the one analysts forget." },
          { id: "o5", text: "A branch firewall that logs 16:23 local time in Tel Aviv logged 14:23 UTC.", answer: true, why: "Subtract the two-hour offset from local time to reach UTC before comparing with any other source." },
          { id: "o6", text: "A phone-system entry at 19:58 India time is 13:28 UTC.", answer: false, why: "19:58 minus 5:30 is 14:28. Subtracting only 6 hours, or the wrong half hour, shifts the call by an hour." },
          { id: "o7", text: "A timestamp that ends in Z is in UTC.", answer: true, why: "Z stands for zero offset, Zulu time. It needs no conversion before it goes in the timeline." },
          { id: "o8", text: "2026-11-04T11:15:30+02:00 and 2026-11-04T09:15:30Z are the same instant.", answer: true, why: "A +02:00 local time is two hours ahead of UTC, so 11:15 local is 09:15 UTC." },
          { id: "o9", text: "2026-11-04T11:15:30+02:00 and 2026-11-04T11:15:30Z are the same instant.", answer: false, why: "The clock reads the same but the offsets differ, so the instants are two hours apart. Always read the suffix." },
          { id: "o10", text: "New York is UTC-4 all year.", answer: false, why: "It is UTC-4 only during summer time and UTC-5 in winter. A conversion needs the date as well as the city." },
          { id: "o11", text: "India does not change its clocks, so Bengaluru is UTC+5:30 all year.", answer: true, why: "A fixed offset makes it the easiest zone to convert, once you remember the half hour." },
          { id: "o12", text: "UTC moves by an hour when Europe changes its clocks.", answer: false, why: "UTC never changes. Local zones move around it, which is why logs are stored in UTC." },
          { id: "o13", text: "09:00 in New York in winter is 14:00 UTC.", answer: true, why: "Winter New York is UTC-5, so add five hours to reach UTC." },
          { id: "o14", text: "A SIEM that displays local time has changed the event's real time.", answer: false, why: "The stored instant is the same. Only the display shifts, so state the zone whenever you write a time down." },
        ],
        lesson: "Store and compare in UTC. Add or subtract the offset, watch half-hour zones like India, remember that summer time moves only local zones, and never compare two times without their zones.",
      },
      {
        kind: "worksheet",
        title: "Which Clock Is It?",
        prompt: "Three people describe the same incident. Turn each statement into UTC before you compare anything.",
        caption: "Statements in the incident channel",
        columns: ["who", "said", "their source"],
        rows: [
          ["New York analyst", "'It started at 09:20'", "SIEM console, set to New York time (EST, UTC-5)"],
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
        kind: "deduce",
        title: "Whose Clock Is Lying?",
        prompt: "Ines fired one test event at every system at exactly 14:30:00 UTC and pasted what each logged. One clock is wrong enough to flip the incident timeline. Which one?",
        nameColumn: "System",
        columns: ["NTP service", "Logged the test event at"],
        suspects: [
          { id: "dc01", name: "DC01", cells: ["active", "14:30:00"] },
          { id: "mailgw", name: "mail-gw", cells: ["active", "14:30:01"] },
          { id: "vpngw", name: "vpn-gw-01", cells: ["inactive, hypervisor syncs the VM", "14:30:02"] },
          { id: "edrrelay", name: "edr-relay", cells: ["inactive", "14:28:02"] },
          { id: "fwhq", name: "fw-tlv-hq", cells: ["active", "16:30:03"] },
        ],
        clues: [
          "The test was fired at exactly 14:30:00 UTC from the reference clock. Two systems logged it within one second.",
          "fw-tlv-hq logs in local Tel Aviv time, UTC+2, with no zone in the line. Converted to UTC it is on time.",
          "The incident is ordered in minutes. A two-second error cannot flip any event, but a two-minute error puts a process before the logon that owns it.",
        ],
        culprit: "edrrelay",
        why: "edr-relay logged the test at 14:28:02: two minutes slow, with no NTP to correct it. Add 2 minutes to its timestamps and PowerShell lands after the logon. fw-tlv-hq only looked two hours off because it logs local time, and vpn-gw-01 has no NTP but sits within two seconds: a risk to monitor, not the cause.",
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
          { id: "fw", q: "What is the firewall event's corrected time (HH:MM:SS)?", hint: "Fast by 3 minutes: subtract 3 minutes.", answer: ["14:05:10"], why: "Not five minutes forty after the process, but forty seconds." },
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
