import type { RoomExperience } from "./types";

// "Operation Three Heads" for the "kerberos-authentication" room.
// Script: docs/campaign/78-kerberos-authentication.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Vale Regional Health (fictional), not the graded tasks' meridian.local records.
// Mentor: Astrid Okonjo, Identity Threat Analyst.
// Signature, Read the Ticket: room 34 names the AD attacks, this room decides between them from
// fields. A hunt in SPL over 4768 and 4769 finds a sweep by its spread of service accounts, and
// a defuse makes the learner choose Kerberoasting, AS-REP roasting or pass-the-ticket from one
// event's fields, in cases where the cipher field decides nothing.
// Game mix: defuse + hunt + intercept.
//
// TASK ORDER CHANGED. The room puts ac1, m1, o1, qf1 and f1 at the end, so the exchange ordering
// comes after the attacks, and f1 and qf1 sit far from the log they refer to. New order, for the
// integrator:
//   krb-r1, krb-r2, krb-q1, krb-o1 | krb-r3, krb-r4, krb-q2 | krb-r5, krb-la1, krb-f1, krb-qf1 |
//   krb-r6, krb-la2, krb-q3, krb-m1 | krb-ac1
//
// Pass-the-ticket is not in this room's readings (room 34 names it), so the defuse primer
// teaches it. The readings cover overpass-the-hash, Golden and Silver.
//
// Lab data differs from the graded tasks: the Kerberoast rounds are an AES burst and a single
// quiet ticket, and the hunt's sweep is five RC4 tickets, never 59 services with one RC4 sample
// (la1, q3, qf1); the AS-REP round carries AES, never RC4 on a retired reporting or FTP account
// (la2, q3); the hunt is SPL over two event codes, never KQL (qf1); the exchange is shown as
// data on a nurse's sign-in and never asked as an order (o1); the session with no ticket events
// is reached by IP address with a 4776, never an all-DC blank (q1); the KDC check uses a payroll
// portal and a web SPN, never a SQL service (q2); the signal drills are responses and row-finding
// on Vale's logs, never signal-to-attack pairs (m1); the boss warm-up is an imaging link, a lift
// gateway and other steady clients under their own records, never a backup job to a NAS (ac1).
//
// Since the April 2026 Kerberos hardening (CVE-2026-20833) an account with
// msDS-SupportedEncryptionTypes unset gets AES by default (reading r3 says so), so the labs use
// explicit attribute values only.

const REALM = "@VALEHEALTH.EXAMPLE";
const DAY = "2026-11-03";

/** A 4769 row. On this event TargetUserName is the requester, written user@REALM. */
const tgs = (time: string, dc: string, who: string, service: string, enc: string, ip: string, status = "0x0") =>
  [`${DAY} ${time}`, dc, "4769", `${who}${REALM}`, service, enc, "", status, `::ffff:${ip}`];

/** A 4768 row. On a failure the cipher is 0xFFFFFFFF, PreAuthType is - and ServiceName is krbtgt/REALM. */
const tgt = (time: string, dc: string, who: string, enc: string, preAuth: string, ip: string, status = "0x0") =>
  [`${DAY} ${time}`, dc, "4768", who, status === "0x0" ? "krbtgt" : "krbtgt/VALEHEALTH", enc, preAuth, status, `::ffff:${ip}`];

export const KERBEROS_AUTHENTICATION: RoomExperience = {
  roomId: "kerberos-authentication",
  codename: "Operation Three Heads",
  theme: "threeheads",
  handler: { name: "Astrid Okonjo", role: "Identity Threat Analyst, Vale Regional Health" },
  briefing: [
    "Vale Regional Health. Three hospitals, 6,400 staff, one Active Directory domain, and every ward system behind a Kerberos ticket.",
    "Kerberos takes its name from the three-headed dog at the gate. Here the heads are the client, the Key Distribution Center (KDC) and the service, and each holds its own key.",
    "This week a ward clerk's password turned up for sale, and Astrid Okonjo has pulled the domain controllers' logs. Somebody has been working on all three heads.",
    "Learn what each message leaves behind, then read the tickets field by field. The field decides, never the alert title.",
  ],
  mission: "Follow one sign-in through the logs, read a ticket's cipher, learn what the KDC never checks, tell three attacks apart from their fields, climb an SPL hunt to one requester, find the tickets with no paper trail, then give the verdict on the last ticket.",
  estimate: "~65 min",
  look: { primary: "#ff7b72", secondary: "#7ee8fa", warn: "#ffd23f" },
  scene: "facilitythreeheads",
  layout: "facility",
  story: {
    intro: { title: "For Sale", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-intro-8bdf151a.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-intro-82c31408.jpg" },
    afterStation: {
      cipher: { title: "The Night Shift", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-ch2-62b81f74.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-ch2-83b26e41.jpg" },
      forged: { title: "The Odd One", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-ch3-cbe50c52.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-ch3-3564bada.jpg" },
      last: { title: "The Last Ticket", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-finale-16c4bc02.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/kerberos-authentication/threeheads-finale-16f8c42c.jpg" },
    },
  },
  stations: [
    {
      id: "office",
      label: "The Ticket Office",
      topic: "The Kerberos exchange · TGT and service ticket · which host logs 4768, 4769, 4771, 4776 and 4624",
      tagline: "Five messages behind one click",
      building: "ticket",
      taskIds: ["krb-r1", "krb-r2", "krb-q1", "krb-o1"],
    },
    {
      id: "cipher",
      label: "The Cipher Field",
      topic: "Encryption types · msDS-SupportedEncryptionTypes · SPNs · what the KDC never checks",
      tagline: "Who chose RC4?",
      building: "vault",
      taskIds: ["krb-r3", "krb-r4", "krb-q2"],
    },
    {
      id: "read",
      label: "Read the Ticket",
      topic: "Kerberoasting · AS-REP roasting · pass-the-ticket · hunting in SPL · responding to a roast",
      tagline: "The field decides",
      building: "lab",
      taskIds: ["krb-r5", "krb-la1", "krb-f1", "krb-qf1"],
    },
    {
      id: "forged",
      label: "No Paper Trail",
      topic: "Overpass-the-hash · Golden and Silver tickets · which secret to rotate",
      tagline: "What's missing is the evidence",
      building: "archive",
      taskIds: ["krb-r6", "krb-la2", "krb-q3", "krb-m1"],
    },
    {
      id: "last",
      label: "The Last Ticket",
      topic: "Weighing spread, rhythm, source and record into one verdict",
      tagline: "A fourth head?",
      building: "emergency",
      taskIds: ["krb-ac1"],
      boss: true,
    },
  ],
  personas: {
    "krb-q1": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Somebody searched the logs properly. Now tell me what that search means." },
    "krb-o1": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Put it back in order for me, start to finish." },
    "krb-q2": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "A colleague has made an argument. Test it." },
    "krb-la1": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Read the record, then tell me what you see." },
    "krb-f1": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Give me the address." },
    "krb-qf1": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Write it so it runs without me." },
    "krb-la2": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Somebody noticed this one by accident. Read it on purpose." },
    "krb-q3": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Two entries, one desk. Name each." },
    "krb-m1": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "Every signal says something. Pair them up." },
    "krb-ac1": { name: "Astrid Okonjo", role: "Identity Threat Analyst", line: "The rule fired and the shift wants an answer. Your call." },
  },
  briefings: {
    // ── Reading 1: the exchange ──
    "krb-r1": [
      {
        kind: "inspect",
        title: "Five Messages, One Sign-In",
        prompt: "07:02, Northfield ward. A nurse starts a shift and opens the EHR (Electronic Health Record). Behind that one click, five Kerberos messages cross the network. Open each line Astrid has laid out, and note who sends it and which key protects it.",
        artifact: "Wire view · n.adeyemi reaches HTTP/ehr.valehealth.example · first sign-in of the shift",
        items: [
          { id: "m1", text: "AS-REQ, client to KDC: n.adeyemi, plus a timestamp encrypted with a key from the user's password", tag: "Authentication Service request", tone: "info", note: "This is pre-authentication: proving you know the password before the KDC hands anything out. The password itself never crosses the network. Every domain controller (DC) is a KDC." },
          { id: "m2", text: "AS-REP, KDC to client: a TGT, plus a session key", tag: "Authentication Service reply", tone: "trust", note: "The Ticket Granting Ticket (TGT) is sealed with a key from the krbtgt account, so only the KDC can read it. The session key is sealed with the client's key, so only the real client can. The nurse carries a TGT without ever being able to open it." },
          { id: "m3", text: "TGS-REQ, client to KDC: the TGT, and the name of the service wanted", tag: "Ticket Granting Service request", tone: "info", note: "No password this time. The TGT is the proof, and it is reused for every service until it expires, 10 hours by default. The service is named by its Service Principal Name (SPN)." },
          { id: "m4", text: "TGS-REP, KDC to client: a service ticket for that one service", tag: "Ticket Granting Service reply", tone: "trust", note: "Sealed with a key from the service account's password, not the nurse's. One ticket per service. That choice of key is why a service ticket is worth stealing." },
          { id: "m5", text: "AP-REQ, client to service: the service ticket", tag: "The service never phones home", tone: "warn", note: "The service decrypts the ticket with its own key and trusts the result. It never asks the KDC. So whoever holds that key, or krbtgt's, can build a ticket offline, and no DC ever hears of it." },
        ],
      },
      {
        kind: "sort",
        title: "Whose Key Locks It?",
        prompt: "Most Kerberos attacks are questions about keys: whose key sealed this, and could someone guess it? Astrid has spread out pieces of this morning's traffic. Sort each one by the key that protects it.",
        primer: {
          title: "Three heads, three keys",
          points: [
            "The **client** has a key from the user's password. The KDC keeps a copy.",
            "The **KDC** has a key from the `krbtgt` account. One account protects every TGT in the domain.",
            "The **service** has a key from the password of the account that runs it. That can be a user-style service account or a computer account.",
            "To find the key, ask who must be able to open this thing. If the client must never read it, the client's key didn't seal it.",
          ],
          example: {
            label: "A worked read: the rota app",
            lines: [
              "A ticket for `HTTP/rota.valehealth.example`, which runs as `svc_rota`.",
              "Who opens it? The rota app, so the key is `svc_rota`'s.",
              "The person who asked for it can carry it, but can't read it.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "client", label: "The client's key" },
          { id: "krbtgt", label: "The krbtgt key" },
          { id: "service", label: "The service account's key" },
        ],
        items: [
          { id: "k1", text: "The timestamp a nurse's laptop sends to prove the password", bucket: "client", why: "The KDC decrypts it with its copy of the user's key. If that works, the password was right." },
          { id: "k2", text: "The TGT a consultant receives at Eastmere", bucket: "krbtgt", why: "Only the KDC ever opens a TGT, at any hospital, so one account's key protects them all." },
          { id: "k3", text: "The session key inside an AS-REP", bucket: "client", why: "The client has to read this one to use the TGT, so it is wrapped in the client's own key." },
          { id: "k4", text: "A service ticket for the pharmacy dispensing app", bucket: "service", why: "The app has to open it, so it is sealed with the key of the account the app runs as." },
          { id: "k5", text: "The TGT an IT admin receives at Southgate", bucket: "krbtgt", why: "Admins get no special treatment. An admin's TGT is sealed with the same krbtgt key as a porter's." },
          { id: "k6", text: "A service ticket for a share on file server VRH-FS03", bucket: "service", why: "A file share runs as the server itself, so here the 'service account' is the computer account, VRH-FS03$." },
        ],
      },
    ],
    // ── Reading 2: which host logs what ──
    "krb-r2": [
      {
        kind: "trace",
        title: "Follow One Session Through the Logs",
        prompt: "A radiologist's session has landed on Astrid's desk, and it's a clean one. Trace it back from the file server to the ticket that paid for it, then look at two more moments from the same morning. Each step is a different log on a different host.",
        lead: "VRH-FS03 logged a session for r.castell, Radiology, at 08:14.",
        primer: {
          title: "Which host logs what",
          points: [
            "**4768** (TGT issued) and **4769** (service ticket issued) are written only on the DC that answered. DCs don't share them, so search every DC.",
            "**4771** is a failed pre-authentication, and failure code `0x18` is a wrong password. **4776** means a DC checked NTLM (NT LAN Manager) credentials: a different protocol with a different trail.",
            "The server a user reaches writes **4624**, with `AuthenticationPackageName` and `LogonType` (3 network, 10 RDP). It says a session began. It says nothing about how the ticket was obtained.",
            "A service never checks with the KDC, so a server never logs a 4769.",
            "One TGT buys many service tickets, so expect one 4768 and then a run of 4769s for up to 10 hours. A renewed TGT logs a 4770, not a 4768, for up to 7 days.",
          ],
          example: {
            label: "The method, on a print server",
            lines: [
              "Start at the target. `PRT-SRV2`: 4624, LogonType 3, package Kerberos, user d.lowe.",
              "Kerberos, so a ticket exists. Search all DCs for a 4769 from d.lowe with ServiceName `PRT-SRV2$`.",
              "Then look back across the ticket's renewable life for the 4768 that started it, and any 4770 that renewed it.",
            ],
          },
          fold: true,
        },
        steps: [
          {
            id: "target", source: "Security log · 4624 · VRH-FS03",
            ask: "Which line is the session in the lead?",
            columns: ["time", "event", "TargetUserName", "LogonType", "AuthenticationPackageName", "IpAddress"],
            rows: [
              ["08:09", "4624", "svc_scanagent", "3", "Kerberos", "10.30.2.40"],
              ["08:14", "4624", "r.castell", "3", "Kerberos", "10.30.5.16"],
              ["08:21", "4624", "m.duarte", "3", "Kerberos", "10.30.3.77"],
            ],
            answer: 1,
            why: "LogonType 3 is a network logon and the package is Kerberos, so some DC issued a ticket. This line can't say which, or when.",
            learned: "08:14 network logon, Kerberos: a ticket exists",
          },
          {
            id: "dc", source: "Security log · all three DCs · r.castell",
            ask: "Which line issued the ticket for the file server?",
            columns: ["time", "Computer", "event", "ServiceName", "TicketEncryptionType", "Status"],
            rows: [
              ["07:03", "VRH-DC-NTH", "4768", "krbtgt", "0x12", "0x0"],
              ["07:03", "VRH-DC-NTH", "4769", "VRH-WS-RAD16$", "0x12", "0x0"],
              ["07:40", "VRH-DC-NTH", "4769", "svc_ehrapp", "0x12", "0x0"],
              ["08:14", "VRH-DC-EST", "4769", "VRH-FS03$", "0x12", "0x0"],
            ],
            answer: 3,
            why: "ServiceName holds the account that owns the SPN, here the server's computer account. Notice the DC: Eastmere answered this one, so a search of Northfield alone would have missed it.",
            learned: "08:14 4769 on VRH-DC-EST, never on the file server",
          },
          {
            id: "tgt", source: "Security log · all three DCs · r.castell",
            ask: "That 4769 needed a TGT. Which line bought it?",
            columns: ["time", "Computer", "event", "ServiceName", "TicketEncryptionType", "Status"],
            rows: [
              ["07:03", "VRH-DC-NTH", "4768", "krbtgt", "0x12", "0x0"],
              ["07:03", "VRH-DC-NTH", "4769", "VRH-WS-RAD16$", "0x12", "0x0"],
              ["07:40", "VRH-DC-NTH", "4769", "svc_ehrapp", "0x12", "0x0"],
              ["08:14", "VRH-DC-EST", "4769", "VRH-FS03$", "0x12", "0x0"],
            ],
            answer: 0,
            why: "One 4768 at 07:03, on another DC, paid for every service ticket after it. A ticket's history can span DCs and more than an hour.",
            learned: "07:03 4768 on VRH-DC-NTH: the TGT behind the session",
          },
          {
            id: "ntlm", source: "VRH-FS03 and all DCs · r.castell · 08:52",
            ask: "At 08:52 r.castell opens \\\\10.30.1.15\\scans, by address, not by name. There is no 4769 for it. Which line shows a DC was involved at all?",
            columns: ["time", "Computer", "event", "detail"],
            rows: [
              ["08:52", "VRH-FS03", "4624", "LogonType 3, AuthenticationPackageName NTLM"],
              ["08:52", "VRH-DC-NTH", "4776", "Credentials validated, Status 0x0"],
              ["08:53", "VRH-FS03", "5140", "Share \\\\*\\scans accessed"],
            ],
            answer: 1,
            why: "An IP address has no SPN to ask for, so Windows fell back to NTLM. No ticket events exist because no ticket did. Read the 4624's package before you read anything into a missing 4769.",
            learned: "08:52 NTLM session: 4776, no 4768 or 4769",
          },
          {
            id: "fail", source: "Security log · VRH-DC-NTH · failures",
            ask: "Earlier, r.castell's sign-in failed twice. Which line is the wrong password?",
            columns: ["time", "event", "TargetUserName", "Status"],
            rows: [
              ["06:59", "4768", "r.castel", "0x6"],
              ["07:00", "4771", "r.castell", "0x18"],
              ["07:03", "4768", "r.castell", "0x0"],
            ],
            answer: 1,
            why: "0x6 on a 4768 means the name doesn't exist: a typo here, and name-guessing when it comes in bulk. A wrong password never appears as a 4768. It is written as a 4771 with 0x18.",
            learned: "4771 0x18 is a wrong password, 4768 0x6 an unknown name",
          },
        ],
      },
    ],
    // ── Reading 3: encryption types ──
    "krb-r3": [
      {
        kind: "anatomy",
        title: "Anatomy of a 4769",
        prompt: "Before you judge a bad ticket, learn a good one. This is a nurse's ordinary ticket for the EHR app, in the fields the DC writes. Scan each one, because every later judgement in this room comes from these fields.",
        source: "Security log · VRH-DC-NTH · EventCode 4769",
        fields: [
          { key: "EventCode", value: "4769", label: "What", note: "A service ticket was requested. Written only on the DC that answered." },
          { key: "TargetUserName", value: "n.adeyemi@VALEHEALTH.EXAMPLE", label: "Who asked", note: "On a 4769 this is the requester, in user@REALM form. The name is misleading: this person's key plays no part in the ticket." },
          { key: "ServiceName", value: "svc_ehrapp", label: "Whose key", note: "The account that owns the SPN, not the SPN string. The ticket is sealed with this account's key, so this is whose password a stolen ticket puts at risk." },
          { key: "TicketEncryptionType", value: "0x12", label: "Cipher", note: "AES256, the value Vale expects. Tells you how the ticket is protected and how dear each offline guess would be." },
          { key: "TicketOptions", value: "0x40810000", note: "Forwardable, Renewable, Canonicalize. A very common value, so it rarely decides anything alone." },
          { key: "Status", value: "0x0", label: "Result", note: "Issued. A failure shows a code instead. 0x20 means a ticket expired, which is routine noise. On a failed request the cipher field reads 0xFFFFFFFF." },
          { key: "IpAddress", value: "::ffff:10.30.4.18", label: "From where", note: "The machine that sent the request, here an IPv4 address in mapped form. It is never the DC's own address unless someone is working on the DC, so this is the host you pivot to." },
          { key: "IpPort", value: "54811", note: "The client's source port. Rarely useful, and some sources record 0." },
        ],
        summary: "Read a 4769 as a sentence: this requester, from this machine, was given a ticket sealed with this account's key, under this cipher. The DC never says why. Whether it was fine comes from what surrounds it: how many services, from where, and whether the requester had any reason to ask.",
      },
      {
        kind: "worksheet",
        title: "Who Can Be Downgraded?",
        prompt: "Astrid has exported four of Vale's service accounts. Before anyone calls RC4 a downgrade, work out who it could happen to. Use the bit values in the primer.",
        primer: {
          title: "Reading the cipher",
          points: [
            "`TicketEncryptionType` is in hex: **0x12** AES256, **0x11** AES128, **0x17** RC4-HMAC, **0x1** and **0x3** DES (extinct, so worth a look whenever seen).",
            "An RC4 key comes almost straight from the account's NT hash, while AES adds real work to every guess. So one guess against RC4 costs far less, and roasting tools ask for it.",
            "The client lists what it supports, but the KDC picks from what the **target** account allows, in `msDS-SupportedEncryptionTypes`, and from the keys that account holds.",
            "That attribute is a sum of bits: `0x4` RC4, `0x8` AES128, `0x10` AES256. So `0x18` is AES only, and `0x1C` still allows RC4.",
            "0x17 raises a question. It doesn't answer one, because old equipment produces it honestly every day.",
          ],
          example: {
            label: "Working one out",
            lines: [
              "`svc_labels` has the value `0x14`, which is `0x10` + `0x4`: AES256 and RC4.",
              "A tool asks for RC4 and the attribute allows it, so the ticket comes back `0x17`.",
              "Set it to `0x10`, and that same request can no longer return RC4.",
            ],
          },
          fold: true,
        },
        caption: "AD export · service accounts · msDS-SupportedEncryptionTypes",
        columns: ["Account", "SPN", "msDS-SupportedEncryptionTypes", "Password last set", "Owner"],
        rows: [
          ["svc_ehrapp", "HTTP/ehr.valehealth.example", "0x18", "2026-09-14", "Clinical Apps"],
          ["svc_pacsarc", "PACSArc/pacs-arc.valehealth.example", "0x4", "2017-03-02", "Imaging"],
          ["svc_rxdisp", "HTTP/rx-disp.valehealth.example", "0x1C", "2021-06-30", "Pharmacy"],
          ["svc_bedboard", "HTTP/bedboard.valehealth.example", "0x10", "2026-08-02", "Facilities"],
        ],
        questions: [
          { id: "count", q: "A roasting tool asks for RC4 on all four accounts. How many tickets come back as 0x17?", hint: "Check each value for the 0x4 bit.", answer: ["2", "two"], why: "svc_pacsarc (0x4) and svc_rxdisp (0x1C, which is 0x10 + 0x8 + 0x4). The other two have no RC4 bit, so the KDC won't use it, whatever the tool asks for." },
          { id: "worst", q: "Which account would you protect first?", hint: "Weigh the cipher together with the age of the password.", answer: ["svc_pacsarc"], why: "RC4 only, and a password from 2017. Both make cracking cheaper, and a password that old may be short. svc_rxdisp is next." },
          { id: "safe", q: "svc_ehrapp is AES only. Does that make its tickets impossible to crack offline? (yes/no)", hint: "What does AES change: the attempt, or the price of each guess?", answer: ["no"], why: "AES makes each guess dearer, but a weak password still falls. The real defence is a long random password, and the attribute only buys time." },
        ],
      },
    ],
    // ── Reading 4: SPNs ──
    "krb-r4": [
      {
        kind: "simulate",
        title: "What Does the KDC Check?",
        prompt: "An analyst's instinct says a ticket means access. Run five requests through both the KDC's checks and the service's own, and watch where each one stops. Then look at which of them the DC logged as a success.",
        primer: {
          title: "What an SPN is, and who may ask",
          points: [
            "A Service Principal Name (SPN) names one service as `class/host`, sometimes with `:port`, and is registered on the account that runs it.",
            "Any domain user can list every SPN with a plain LDAP (Lightweight Directory Access Protocol) query. It takes no privileges.",
            "At the service ticket step the KDC checks two things only: is the TGT valid, and does the SPN exist? It checks no group and no access list.",
            "Whether you may use the service is decided by the service, when you present the ticket.",
            "A ticket can be carried away and guessed at offline. The DC logged one 4769 and hears nothing more.",
          ],
          example: {
            label: "The two questions, on the catering menu app",
            lines: [
              "`p.nowak` asks for `HTTP/menus.valehealth.example`.",
              "TGT valid? Yes. SPN registered? Yes. So: 4769, Status `0x0`.",
              "Nobody has yet asked if `p.nowak` is allowed in. The app decides that later.",
            ],
          },
          fold: true,
        },
        checks: [
          { name: "KDC: TGT valid?", question: "Is the requester's TGT still good?" },
          { name: "KDC: SPN exists?", question: "Is this SPN registered to an account?" },
          { name: "Service: let in?", question: "Presented with the ticket, does the service admit this identity?" },
        ],
        scenarios: [
          { id: "nurse", label: "A nurse opens the EHR", detail: "n.adeyemi, TGT from 07:02, asks for HTTP/ehr.valehealth.example.", results: ["pass", "pass", "pass"], why: ["Issued this morning.", "Registered to svc_ehrapp.", "Clinical staff are allowed in."], verdict: "4769 with Status 0x0, then a 4624 on the app server. The ordinary shape: the ticket is asked for, then used." },
          { id: "porter", label: "A porter asks for the payroll portal", detail: "s.quill, no role in Finance, asks for HTTP/payroll.valehealth.example.", results: ["pass", "pass", "fail"], why: ["A good TGT, and that's all the KDC needs from a person.", "The SPN is registered.", "The portal refuses: no Finance role."], verdict: "The DC logged a success, 4769 Status 0x0. The refusal came later, at the service, on a different host. So having no rights on a service never stopped anyone getting its ticket." },
          { id: "stale", label: "A laptop back after 12 hours", detail: "g.mbeki's TGT is past its lifetime when the app is reopened.", results: ["fail", "pass", "fail"], why: ["Expired.", "The SPN is fine.", "Never reached: there is no ticket to present."], verdict: "A 4769 failure with 0x20, ticket expired. Routine noise: Windows simply gets a fresh ticket. Don't chase it." },
          { id: "typo", label: "A script with a mistyped name", detail: "A monitoring script asks for HTTP/ehr-oldd.valehealth.example.", results: ["pass", "fail", "fail"], why: ["The TGT is good.", "No account owns that name.", "Never reached."], verdict: "Failure code 0x7, server not found in the Kerberos database. No ticket exists, so nothing can be carried away." },
          { id: "away", label: "A ticket that is never used", detail: "A phished clerk's session asks for HTTP/rx-disp.valehealth.example, then nothing reaches the app.", results: ["pass", "pass", "fail"], why: ["A stolen session still holds a valid TGT.", "The SPN came from a plain LDAP query.", "Never presented: the app sees nothing at all."], verdict: "The DC logged one success, and the ticket is already gone. Guessing happens on the attacker's own machine, so nothing more is logged. The ticket itself is the stolen goods, the moment it is issued." },
        ],
      },
    ],
    // ── Reading 5: the roasts, and the signature labs ──
    "krb-r5": [
      {
        kind: "defuse",
        title: "Read the Ticket",
        prompt: "Four tickets from this month's case file, and the clock is on. Each one is an attack. Read the fields and cut the wire that names it. Watch out: the cipher field will try to talk you into the wrong answer.",
        device: "Ticket reader · Vale case file",
        seconds: 95,
        primer: {
          title: "Three attacks, and the fields that split them",
          points: [
            "**Kerberoasting** (T1558.003): a valid user asks for service tickets to crack offline, and gets the password of the account behind the SPN. Look at **4769**: usually many ServiceName values from one requester, or a ticket that is never used.",
            "**AS-REP roasting** (T1558.004): an account has 'Do not require Kerberos preauthentication' set (DONT_REQ_PREAUTH), so the KDC answers anyone who names it. No credentials needed, and the crackable part holds that account's own password. Look at **4768** with **PreAuthType 0**. A normal password logon shows 2.",
            "No 4771 comes before an AS-REP roast: a 4771 records pre-authentication that failed, and this was never attempted.",
            "**Pass-the-ticket** (T1550.003): a real ticket is stolen from memory and replayed, so nothing is cracked. A genuine 4768 exists, but the next **4769 comes from a different IpAddress**, one the account has no TGT from. Rule out VPN and address changes first.",
            "Ask in this order: which event? On a 4768, what is PreAuthType? On a 4769, how many services, and does the address match the TGT's?",
          ],
          example: {
            label: "A worked read that clears a kiosk",
            lines: [
              "`4768`, `lobby_kiosk`, PreAuthType `2`, Status `0x0`. The password was proved: no AS-REP roast.",
              "`4769` a minute later, same account, one ServiceName, used at once on the app server.",
              "IpAddress matches the 4768. No replay, no sweep, and the ticket was used. Clean.",
            ],
          },
          fold: true,
        },
        rounds: [
          {
            id: "noproof",
            state: "VRH-DC-EST, 4768. TargetUserName=svc_faxgw, ServiceName=krbtgt, PreAuthType=0, TicketEncryptionType=0x12, Status=0x0, IpAddress=::ffff:10.30.7.52. No 4771 for this account all month.",
            wires: [
              { id: "ptt", label: "Pass-the-ticket" },
              { id: "kerb", label: "Kerberoasting" },
              { id: "asrep", label: "AS-REP roasting" },
            ],
            cut: "asrep",
            hint: "Which event is this, and was a password ever proved?",
            why: "PreAuthType 0 on a 4768: the KDC asked for no proof. AES in the cipher field changes nothing, because the question is whether a password was proved. Whoever sent this may hold no credentials at all, just a name.",
          },
          {
            id: "sweep",
            state: "VRH-DC-NTH, 4769, 02:14 to 02:18. TargetUserName=m.oyelaran@VALEHEALTH.EXAMPLE, 31 different ServiceName values, all user-style service accounts, TicketEncryptionType=0x12 on every row, Status=0x0, one IpAddress.",
            wires: [
              { id: "kerb", label: "Kerberoasting" },
              { id: "asrep", label: "AS-REP roasting" },
              { id: "ptt", label: "Pass-the-ticket" },
            ],
            cut: "kerb",
            hint: "Count what changes from row to row.",
            why: "One requester, 31 service accounts, four minutes. AES makes each guess dearer but doesn't stop the harvest, so a clean cipher never clears a sweep. The shape decides.",
          },
          {
            id: "moved",
            state: "VRH-DC-NTH, 4769. TargetUserName=l.haddad@VALEHEALTH.EXAMPLE, ServiceName=svc_ehrapp, TicketEncryptionType=0x12, Status=0x0, IpAddress=::ffff:10.30.9.77 (VRH-FIN-LT06). l.haddad's 4768 at 06:52: PreAuthType=2, IpAddress=::ffff:10.30.4.63 (VRH-WS-CAR63). No VPN, and no 4768 from .77 for this account.",
            wires: [
              { id: "asrep", label: "AS-REP roasting" },
              { id: "ptt", label: "Pass-the-ticket" },
              { id: "kerb", label: "Kerberoasting" },
            ],
            cut: "ptt",
            hint: "Compare the 4769's address with the 4768's.",
            why: "A genuine TGT went to a cardiology PC, then was spent from a finance laptop that never received one. One normal service and a normal cipher, so nothing else looks wrong. The attacker isn't cracking anything: the ticket is already usable.",
          },
          {
            id: "quiet",
            state: "VRH-DC-STH, 4769. TargetUserName=b.achterberg@VALEHEALTH.EXAMPLE, ServiceName=svc_rxdisp, TicketEncryptionType=0x17, Status=0x0, IpAddress matches the user's own 4768. One ticket today. b.achterberg works in Estates, and no logon on the dispensing server followed.",
            wires: [
              { id: "ptt", label: "Pass-the-ticket" },
              { id: "asrep", label: "AS-REP roasting" },
              { id: "kerb", label: "Kerberoasting" },
            ],
            cut: "kerb",
            hint: "A ticket is normally asked for in order to be used.",
            why: "The same machine as the TGT, so no replay. A 4769, so no AS-REP roast. A ticket for a service nobody in Estates uses, on an account that allows RC4, and never presented: a careful roast of one account. A burst is the common shape, not the only one.",
          },
        ],
        lesson: "Read the event first: a 4768 is about one account's TGT, a 4769 about a service ticket. On a 4768, PreAuthType 0 means no proof. On a 4769, count ServiceName values, check the ticket was used, and compare IpAddress with the account's 4768. The cipher didn't decide any of these four.",
      },
      {
        kind: "hunt",
        title: "The Ticket Ladder",
        prompt: "Now find one yourself. It's the night of 3 November, and the sold password belongs to a ward clerk. In SPL (Search Processing Language, Splunk's query language), build a hunt over the DCs' 4768 and 4769 events, one line at a time. Every result you see is what that line really returns.",
        language: "SPL",
        console: "Search",
        start: "index=wineventlog EventCode IN (4768, 4769)",
        goal: "one row: the requester sweeping service accounts, and the address it worked from",
        primer: {
          title: "SPL for this hunt",
          points: [
            "Each `|` passes rows to the next command. `search` filters and takes wildcards, so `ServiceName!=\"*$\"` means does not end in $.",
            "`stats count by a, b` gives one row per combination plus a `count` column. Every other field is gone afterwards.",
            "A count of rows is not a count of different things. Run `stats` twice and the second count is distinct values. `stats dc(field)` does it in one line.",
            "A ServiceName ending in `$` is a computer account, with a long random password changed every 30 days: not worth roasting. `krbtgt` is the KDC itself.",
            "The field writes ciphers in hex, as in the event, and the requester as user@REALM.",
          ],
          example: {
            label: "Rows against distinct values, on print jobs",
            lines: [
              "`index=print | stats count by user, printer` gives one row per pair.",
              "`| stats count by user` then counts the printers each user touched, not the pages.",
            ],
          },
          fold: true,
        },
        tables: [
          {
            name: "index=wineventlog EventCode IN (4768, 4769)",
            note: "Kerberos ticket events from all three DCs, overnight. PreAuthType exists on 4768 only.",
            columns: ["_time", "Computer", "EventCode", "TargetUserName", "ServiceName", "TicketEncryptionType", "PreAuthType", "Status", "IpAddress"],
            rows: [
              tgt("00:12:08", "VRH-DC-NTH", "s.brandt", "0x12", "2", "10.30.2.41"),
              tgs("00:12:09", "VRH-DC-NTH", "s.brandt", "VRH-WS-ICU04$", "0x12", "10.30.2.41"),
              tgs("00:12:30", "VRH-DC-NTH", "s.brandt", "svc_ehrapp", "0x12", "10.30.2.41"),
              tgs("00:40:11", "VRH-DC-STH", "VRH-WS-PHM02$", "VRH-FS03$", "0x12", "10.30.6.12"),
              tgs("00:55:02", "VRH-DC-EST", "svc_modlink", "svc_pacsarc", "0x17", "10.30.5.70"),
              tgs("01:10:44", "VRH-DC-NTH", "s.brandt", "krbtgt", "0x12", "10.30.2.41"),
              tgs("01:25:02", "VRH-DC-EST", "svc_modlink", "svc_pacsarc", "0x17", "10.30.5.70"),
              tgs("01:31:05", "VRH-DC-NTH", "s.brandt", "svc_ehrapp", "0xFFFFFFFF", "10.30.2.41", "0x20"),
              tgs("01:55:02", "VRH-DC-EST", "svc_modlink", "svc_pacsarc", "0x17", "10.30.5.70"),
              tgs("02:05:11", "VRH-DC-STH", "svc_assetscan", "VRH-PRN07$", "0x17", "10.30.6.90"),
              tgs("02:05:12", "VRH-DC-STH", "svc_assetscan", "VRH-PRN08$", "0x17", "10.30.6.90"),
              tgs("02:05:14", "VRH-DC-STH", "svc_assetscan", "VRH-PRN09$", "0x17", "10.30.6.90"),
              tgs("02:05:15", "VRH-DC-STH", "svc_assetscan", "VRH-PRN11$", "0x17", "10.30.6.90"),
              tgs("02:05:17", "VRH-DC-STH", "svc_assetscan", "VRH-PRN12$", "0x17", "10.30.6.90"),
              tgs("02:25:02", "VRH-DC-EST", "svc_modlink", "svc_pacsarc", "0x17", "10.30.5.70"),
              tgt("02:38:40", "VRH-DC-NTH", "t.rowes", "0xFFFFFFFF", "-", "10.30.7.52", "0x6"),
              tgt("02:39:02", "VRH-DC-NTH", "t.rowe", "0x12", "2", "10.30.7.52"),
              tgs("02:41:10", "VRH-DC-NTH", "t.rowe", "svc_pacsarc", "0x17", "10.30.7.52"),
              tgs("02:41:11", "VRH-DC-NTH", "t.rowe", "svc_rxdisp", "0x17", "10.30.7.52"),
              tgs("02:41:13", "VRH-DC-NTH", "t.rowe", "svc_ehrapp", "0x12", "10.30.7.52"),
              tgs("02:41:14", "VRH-DC-NTH", "t.rowe", "svc_labint", "0x17", "10.30.7.52"),
              tgs("02:41:16", "VRH-DC-NTH", "t.rowe", "rx_sqlagent", "0x17", "10.30.7.52"),
              tgs("02:41:17", "VRH-DC-NTH", "t.rowe", "svc_bedboard", "0x12", "10.30.7.52"),
              tgs("02:41:19", "VRH-DC-NTH", "t.rowe", "svc_hl7bridge", "0x17", "10.30.7.52"),
              tgs("02:41:48", "VRH-DC-NTH", "t.rowe", "svc_rxdisp", "0x17", "10.30.7.52"),
              tgt("02:52:14", "VRH-DC-EST", "svc_faxgw", "0x12", "0", "10.30.7.52"),
              tgs("02:55:02", "VRH-DC-EST", "svc_modlink", "svc_pacsarc", "0x17", "10.30.5.70"),
              tgs("03:25:02", "VRH-DC-EST", "svc_modlink", "svc_pacsarc", "0x17", "10.30.5.70"),
            ],
          },
        ],
        rungs: [
          {
            id: "kind", ask: "Line 2: a sweep across services is a story about service tickets. Keep that event.",
            choices: [
              { id: "a", text: "| search EventCode=4768", why: "These are TGTs, so ServiceName is krbtgt on every good row and there is no spread to measure. Do look at the row with PreAuthType 0 before you move on: it is a second hunt.", apply: { op: "where", col: "EventCode", test: "eq", value: "4768" } },
              { id: "b", text: "| search EventCode=4769", right: true, why: "One row per service ticket request: the requester in TargetUserName, the account whose key sealed it in ServiceName.", apply: { op: "where", col: "EventCode", test: "eq", value: "4769" } },
              { id: "c", text: "| search EventCode=4771", why: "No rows. A 4771 is a failed pre-authentication and isn't in the base search. A roast succeeds, so it wouldn't show there anyway.", apply: { op: "where", col: "EventCode", test: "eq", value: "4771" } },
            ],
          },
          {
            id: "owner", ask: "Line 3: machines ask for machine tickets all night. Keep tickets for accounts where a person set the password.",
            choices: [
              { id: "a", text: '| search ServiceName="svc_*"', why: "rx_sqlagent has vanished. Not every service account follows the naming rule, and the ones that don't are often the oldest. Say what you're excluding, not what you hope the rest is called.", apply: { op: "where", col: "ServiceName", test: "has", value: "svc_" } },
              { id: "b", text: '| search TargetUserName!="*$"', why: "Nothing changed. On a 4769 this field ends in @REALM, so *$ never matches. And it would filter who asked, not whose key sealed the ticket.", apply: { op: "where", col: "TargetUserName", test: "notin", value: ["no-such-account"] } },
              { id: "c", text: '| search ServiceName!="*$" ServiceName!="krbtgt"', right: true, why: "Computer accounts and the KDC are gone, and with them svc_assetscan's five printers. What's left is sealed with keys a person chose.", apply: { op: "where", col: "ServiceName", test: "notin", value: ["VRH-WS-ICU04$", "VRH-FS03$", "VRH-PRN07$", "VRH-PRN08$", "VRH-PRN09$", "VRH-PRN11$", "VRH-PRN12$", "krbtgt"] } },
            ],
          },
          {
            id: "cipher", ask: "Line 4: Vale's baseline is AES. Keep the tickets under the cipher that baseline doesn't expect.",
            choices: [
              { id: "a", text: "| search TicketEncryptionType=23", why: "No rows. RC4-HMAC is encryption type 23 in decimal, and this field is written in hex, so it reads 0x17.", apply: { op: "where", col: "TicketEncryptionType", test: "eq", value: "23" } },
              { id: "b", text: "| search TicketEncryptionType=0x17", right: true, why: "Two of t.rowe's tickets just dropped out: the AES-only accounts. That's the price of this line. It makes a net for RC4 sweeps, and a sweep of AES-only accounts needs the same search without it.", apply: { op: "where", col: "TicketEncryptionType", test: "eq", value: "0x17" } },
              { id: "c", text: "| search TicketEncryptionType=0x12", why: "That's the baseline you were asked to set aside, including a nurse's ordinary ticket.", apply: { op: "where", col: "TicketEncryptionType", test: "eq", value: "0x12" } },
            ],
          },
          {
            id: "pairs", ask: "Line 5: a repeated request isn't a wider one. Roll up to one row per requester, address and service.",
            choices: [
              { id: "a", text: "| stats count by TargetUserName", why: "svc_modlink and t.rowe tie on 6, and that's misleading: one is a client renewing a single ticket. This counts requests, not services.", apply: { op: "summarize", by: ["TargetUserName"], as: "count" } },
              { id: "b", text: "| stats count by ServiceName", why: "Now you know which accounts were touched, and you've lost who asked.", apply: { op: "summarize", by: ["ServiceName"], as: "count" } },
              { id: "c", text: "| stats count by TargetUserName, IpAddress, ServiceName", right: true, why: "Six rows: svc_modlink's one pair, and five for t.rowe. t.rowe's two tickets for svc_rxdisp are now a single row.", apply: { op: "summarize", by: ["TargetUserName", "IpAddress", "ServiceName"], as: "count" } },
            ],
          },
          {
            id: "spread", ask: "Line 6: now count how many different services each requester touched, and keep the address.",
            choices: [
              { id: "a", text: "| stats count by ServiceName", why: "That counts requesters per service, the wrong way round. The question is about the person asking.", apply: { op: "summarize", by: ["ServiceName"], as: "count" } },
              { id: "b", text: "| stats count by TargetUserName, IpAddress", right: true, why: "Each row coming in was one pair, so count is now distinct services: svc_modlink 1, t.rowe 5. In one line that's stats dc(ServiceName), and in KQL it's dcount(ServiceName).", apply: { op: "summarize", by: ["TargetUserName", "IpAddress"], as: "count" } },
              { id: "c", text: "| stats count by TargetUserName", why: "The count is right, but the address is gone, and the address is where you go next.", apply: { op: "summarize", by: ["TargetUserName"], as: "count" } },
            ],
          },
          {
            id: "finish", ask: "Line 7: keep what looks like a sweep. Vale has few service accounts, so choose a threshold that fits this estate.",
            choices: [
              { id: "a", text: "| where count=1", why: "That's the opposite: it keeps the imaging client asking for its one service.", apply: { op: "where", col: "count", test: "eq", value: "1" } },
              { id: "b", text: "| where count>=50", why: "No rows. A number copied from a bigger estate misses a small, careful sweep. Vale doesn't have 50 service accounts worth roasting, and neither would your attacker's list.", apply: { op: "where", col: "count", test: "eq", value: "50" } },
              { id: "c", text: "| where count>=3", right: true, why: "One row: t.rowe, from one address, five service accounts under RC4 in under a minute. Three is low enough to catch a short list, and high enough to pass a client doing its job.", apply: { op: "where", col: "count", test: "notin", value: ["1", "2"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "Read a sweep in this order: service tickets, accounts a person set the password on, the unexpected cipher, one row per pair, then distinct services per requester. The IpAddress in the answer is the host to pivot to, never the DC. A rule in production also bins time, so spread is measured over minutes, not a whole night. And the starting search showed you a row with PreAuthType 0: that's the sister hunt, EventCode=4768 PreAuthType=0.",
      },
      {
        kind: "sort",
        title: "Which Password Goes First?",
        prompt: "The sweep reached seven service accounts, and Vale can only change service passwords a few at a time without stopping ward systems. Guessing happens offline, so no log will say which password is about to fall. Astrid wants a running order, built from what each ticket and account tell you. Two names on the list don't belong in the queue at all.",
        buckets: [
          { id: "first", label: "First: cheap to crack" },
          { id: "next", label: "Next: ticket gone, slower to crack" },
          { id: "none", label: "No key in these tickets" },
        ],
        items: [
          { id: "s1", text: "svc_pacsarc: RC4 ticket taken, password from 2017", bucket: "first", why: "The cheapest cipher and the oldest password in the set. Its RC4-only setting means the vendor has to be part of the fix." },
          { id: "s2", text: "rx_sqlagent: RC4 ticket taken, password from 2018, no owner on file", bucket: "first", why: "Old, and nobody to ask. An unowned account is often the one nobody dares change, so it keeps its weak password longest." },
          { id: "s3", text: "svc_rxdisp: RC4 ticket taken, password from 2021", bucket: "first", why: "It allows RC4 and has AES too. An account only gets fresh AES keys from a password change, so this is the moment to set it AES only." },
          { id: "s4", text: "svc_labint: RC4 ticket taken, password from 2022", bucket: "first", why: "Each guess is cheap and the password was chosen by hand. It goes after the older ones, but still ahead of the AES tickets." },
          { id: "s5", text: "svc_hl7bridge: RC4 ticket taken, 30 random characters set last month", bucket: "next", why: "RC4 makes each guess cheap, but no number of cheap guesses finds a long random password. Password strength outranks the cipher." },
          { id: "s6", text: "svc_ehrapp: AES ticket taken, password set in September", bucket: "next", why: "The ticket still left the building, so it still gets changed. AES and a recent password buy time, not immunity." },
          { id: "s7", text: "svc_bedboard: AES ticket taken, password set in August", bucket: "next", why: "Same as the EHR account: slower to crack, not out of reach." },
          { id: "s8", text: "t.rowe: the account that asked for all of them", bucket: "none", why: "A requester's key seals none of the tickets it asks for. The account is compromised and has its own reset, but cracking these tickets can't reveal its password." },
          { id: "s9", text: "svc_modlink: asked for its one usual ticket all night", bucket: "none", why: "Also a requester. Its ticket is sealed with svc_pacsarc's key, not its own." },
        ],
      },
    ],
    // ── Reading 6: overpass, Golden, Silver ──
    "krb-r6": [
      {
        kind: "trace",
        title: "The Missing Receipt",
        prompt: "After the roast, the intruder got quieter. Every ticket should have a receipt: a TGT has a 4768, a service ticket a 4769, a session a 4624. Three logs from this week, and in each one a single row breaks the pattern. Find it.",
        lead: "Astrid's note: the attacker has stopped asking the KDC politely.",
        primer: {
          title: "Three shortcuts around the password",
          points: [
            "**Overpass-the-hash** (T1550.002): a stolen NT hash acts as the key for a normal AS-REQ. Pre-authentication still happens, so `PreAuthType` is **2**. A hash alone can't produce AES keys, so look for **0x17 on a 4768** in an AES estate. That PreAuthType is how it differs from an AS-REP roast.",
            "**Golden Ticket**: with the krbtgt hash, usually from DCSync, a TGT is forged offline, so no AS-REQ is sent. Using it produces a normal **4769**, with **no 4768** anywhere for that logon.",
            "**Silver Ticket**: with a service account's hash, the service ticket itself is forged. The service trusts its own key, so **no 4768 or 4769** exists on any DC. The only trace is the target's 4624.",
            "A missing event proves nothing until you've searched every DC across the ticket's renewable life, with auditing confirmed. A renewed TGT logs a 4770, not a 4768, for up to 7 days. Check 4770s before you call a TGT forged.",
            "NTLM leaves no ticket events either, so read the target's `AuthenticationPackageName` first.",
          ],
          example: {
            label: "The method, on an account with nothing to hide",
            lines: [
              "Target: 4624, Kerberos, `pharm_kiosk`, 10:15.",
              "All DCs: a 4769 for that server at 10:15. Receipt found.",
              "Back across the ticket's renewable life: a 4768 at 06:40, PreAuthType 2, AES, same address. Receipt found.",
              "Every step has its paper, so nothing was forged.",
            ],
          },
          fold: true,
        },
        steps: [
          {
            id: "hash", source: "Security log · 4768 · all DCs · Tuesday morning",
            ask: "Every user at Vale has AES keys. Which TGT was built from a stolen hash?",
            columns: ["time", "Computer", "TargetUserName", "PreAuthType", "TicketEncryptionType", "Status", "IpAddress"],
            rows: [
              ["06:58", "VRH-DC-NTH", "p.varga", "2", "0x12", "0x0", "10.30.3.21"],
              ["07:11", "VRH-DC-STH", "j.lindahl", "2", "0x17", "0x0", "10.30.7.52"],
              ["07:13", "VRH-DC-STH", "o.marchetti", "2", "0x12", "0x0", "10.30.8.14"],
              ["07:20", "VRH-DC-EST", "svc_kioskupd", "0", "0x12", "0x0", "10.30.7.52"],
            ],
            answer: 1,
            why: "PreAuthType 2 says pre-authentication happened, and RC4 where AES is the norm says the key came from a hash. The PreAuthType 0 row is the near miss: no proof was given at all, and that's the roast from the last station, on another account.",
            learned: "j.lindahl: real TGT, real pre-auth, built from a hash",
          },
          {
            id: "forged", source: "Security log · 4768, 4769 and 4770 · all DCs · seven days back",
            ask: "Every 4769 is paid for by a TGT. Which account is spending one that no DC issued? Pick its first row.",
            columns: ["time", "Computer", "event", "account", "ServiceName", "TicketEncryptionType"],
            rows: [
              ["09:02", "VRH-DC-NTH", "4768", "a.novak", "krbtgt", "0x12"],
              ["09:03", "VRH-DC-NTH", "4769", "a.novak@VALEHEALTH.EXAMPLE", "svc_ehrapp", "0x12"],
              ["09:40", "VRH-DC-EST", "4769", "adm.kowal@VALEHEALTH.EXAMPLE", "VRH-DC-NTH$", "0x12"],
              ["09:41", "VRH-DC-EST", "4769", "adm.kowal@VALEHEALTH.EXAMPLE", "VRH-FS03$", "0x12"],
              ["09:44", "VRH-DC-NTH", "4768", "g.mbeki", "krbtgt", "0x12"],
              ["09:44", "VRH-DC-NTH", "4769", "g.mbeki@VALEHEALTH.EXAMPLE", "svc_bedboard", "0x12"],
            ],
            answer: 2,
            why: "a.novak and g.mbeki each have a 4768. adm.kowal has service tickets and no 4768 or 4770 on any DC. Somebody made that TGT without a KDC, which takes krbtgt's key. AES on the row clears nothing: that cipher belongs to the service ticket the KDC issued, and says nothing about how the TGT behind it was made.",
            learned: "adm.kowal: 4769s with nothing behind them",
          },
          {
            id: "session", source: "VRH-RX01 logons and all DCs · Thursday",
            ask: "Every Kerberos session on the dispensing server should trace back to a DC. Which one doesn't?",
            columns: ["time", "Computer", "event", "account", "package or ServiceName"],
            rows: [
              ["10:30", "VRH-RX01", "4624", "c.ferrer", "Kerberos"],
              ["10:30", "VRH-DC-STH", "4769", "c.ferrer@VALEHEALTH.EXAMPLE", "svc_rxdisp"],
              ["10:50", "VRH-RX01", "4624", "t.okafor", "NTLM"],
              ["11:05", "VRH-RX01", "4624", "e.ryan", "Kerberos"],
            ],
            answer: 3,
            why: "c.ferrer's session has its 4769, and t.okafor's is NTLM, so no ticket was expected. e.ryan's says Kerberos, and no DC has any record of it. A service ticket was built with svc_rxdisp's own key, which is an account you watched being roasted.",
            learned: "e.ryan: a Kerberos session no DC ever issued",
          },
        ],
      },
      {
        kind: "match",
        title: "Whose Secret Burns?",
        prompt: "Naming the attack is half the job, because each one burns a different secret. Astrid's five open cases need the right fix. Match each case to the response that closes it.",
        pairs: [
          { id: "faxgw", left: "svc_faxgw handed out an AS-REP to someone who proved nothing", right: "Change that password now, then list every account carrying the no-pre-auth flag", why: "Setting the flag back stops the next attempt, not the blob already taken, and logs can't show if it was cracked. If nobody uses the account, remove it: Active Directory never disables an account because its application retired, and a name is all the attacker needs." },
          { id: "lindahl", left: "j.lindahl's TGT was built from a stolen NT hash", right: "Change the user's password, and go to the machine whose memory gave it up", why: "The hash came from LSASS (the process holding sign-in secrets) on some host. Find it, or the same thing happens again." },
          { id: "kowal", left: "adm.kowal is spending a TGT that no DC issued", right: "Reset krbtgt twice, allowing replication between resets", why: "Every TGT in the domain is sealed with that key, and the account keeps its previous password too, so one reset leaves the forged ticket working." },
          { id: "ryan", left: "e.ryan's session on VRH-RX01 has no ticket on any DC", right: "Change that one service account's password", why: "A forged service ticket needs that account's key and nothing wider. krbtgt was not involved." },
          { id: "haddad", left: "l.haddad's real ticket is being replayed from another machine", right: "End the sessions and clear tickets on both hosts", why: "A ticket stays valid until it expires, so a password change alone doesn't stop it. Then find how it left the first host." },
        ],
      },
    ],
    // ── Boss warm-up: reading an RC4 ticket in context ──
    "krb-ac1": [
      {
        kind: "sort",
        title: "Three Ways to Close an Alert",
        prompt: "Before the last ticket, Astrid wants one habit fixed. Whether a rule was right and whether the activity was bad are two separate questions. Here are six closed alerts from other rules at Vale: sort each by the verdict it should have carried.",
        primer: {
          title: "Three verdicts",
          points: [
            "**True positive**: the rule saw something real, and it is an attack.",
            "**Benign true positive**: the rule saw something real, and it is authorised or expected. Close it with the justification, and keep the rule.",
            "**False positive**: the rule was wrong about what happened: a bad parser, bad logic, an event that didn't occur. Fix the rule.",
            "The test between the last two: did the rule see what it says it saw?",
            "Authorised means a record you can cite, such as a change ticket or the owner's confirmation. A guess isn't a record, so ask IT.",
          ],
          example: {
            label: "One alert, worked",
            lines: [
              "Rule: new local admin on a workstation. It fired on `VRH-WS-LAB03`.",
              "The admin really was added, so the rule saw what it says.",
              "CHG-40117 shows the helpdesk did it for an analyser install. Benign true positive.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "tp", label: "True positive" },
          { id: "btp", label: "Benign true positive" },
          { id: "fp", label: "False positive" },
        ],
        items: [
          { id: "v1", text: "'Mass file rename' fired. Imaging's migration script was renaming archive folders, as CHG-40233 scheduled.", bucket: "btp", why: "The renames happened, so the rule was right. The record makes them expected." },
          { id: "v2", text: "'New service on a DC' fired. A parser split one log line in two, and no such service exists.", bucket: "fp", why: "Nothing happened as the rule described. The fix belongs in the parser." },
          { id: "v3", text: "'PowerShell download' fired. The script pulled a file from 203.0.113.60, and nobody in IT recognises it.", bucket: "tp", why: "Real activity, no owner, no record. That's an attack until shown otherwise." },
          { id: "v4", text: "'Admin logon after hours' fired. The on-call DBA signed in during a logged major incident, and the rota confirms it.", bucket: "btp", why: "The logon was real. The incident record and the rota are what make it fine." },
          { id: "v5", text: "'Over 20 failed logons' fired. A dashboard join counted each event three times, and the true figure was 7.", bucket: "fp", why: "The threshold was never met, so the rule's logic is what needs fixing." },
          { id: "v6", text: "'Mailbox forwarding rule' fired. A forward to a personal address appeared after a sign-in from an unknown device.", bucket: "tp", why: "Real, unexplained, and in a known attack pattern." },
        ],
      },
      {
        kind: "intercept",
        title: "Escalate or Backlog?",
        prompt: "A new rule flags every 0x17 ticket, and the first morning's hits are dropping in. Escalate what could be an attack. Send to the backlog what's old equipment with a record behind it, for fixing when it can be fixed. Read the line under each ticket, because that's where the answer is.",
        protect: "the on-call analyst",
        blockLabel: "Escalate",
        passLabel: "Backlog",
        seconds: 12,
        primer: {
          title: "Four questions for any RC4 ticket",
          points: [
            "**Spread**: how many different services did this requester touch, and is that normal for it?",
            "**Rhythm**: does it repeat on a steady schedule over weeks, or did it just appear?",
            "**Source**: is it the host that should be doing this?",
            "**Record**: is there a change ticket or vendor note saying why it can't use AES?",
            "All four calm: the rule was right and nothing is wrong today. Log the account for remediation. Any one off: keep going.",
          ],
          example: {
            label: "The building gateway",
            lines: [
              "`svc_bms` gets a `0x17` ticket for `HTTP/bms-gw.valehealth.example`.",
              "A month of 4769s: one service, every six hours, always `10.30.11.8`, the gateway.",
              "CHG-40188 says the firmware has no AES.",
              "Four calm answers, so it goes on the backlog until the firmware changes.",
            ],
          },
          fold: true,
        },
        items: [
          { id: "t1", text: "svc_modlink, 0x17 for svc_pacsarc", sub: "Every 30 minutes for 90 days, gateway 10.30.5.70, CHG-39120 on file", bad: false, why: "One service, a steady rhythm, the right host and a record. It waits for the archive vendor to ship AES." },
          { id: "t2", text: "o.brennan, 0x17 for 22 services", sub: "11 minutes, an Estates PC, no earlier RC4 from this user", bad: true, why: "A person, 22 services, nothing before today. That's the spread you hunted." },
          { id: "t3", text: "svc_assetscan, 0x17 for five printer accounts", sub: "Nightly at 02:05, scanner host 10.30.6.90, CHG-38811: the printers have no AES", bad: false, why: "Spread alone isn't enough. These are computer accounts, on a schedule, from a known scanner, with a record." },
          { id: "t4", text: "svc_modlink, 0x17 for svc_rxdisp", sub: "Once, at 04:12, gateway 10.30.5.70, no record", bad: true, why: "A known account, but it has only ever asked for one service. A quiet client asking for something new is the finding." },
          { id: "t5", text: "svc_labint, 0x17 for its usual analyser service", sub: "Daily at 05:00 for a year, but today from 10.30.7.52", bad: true, why: "Spread and rhythm are calm, and the source has changed. That address isn't this account's home, and you've met it before." },
          { id: "t6", text: "h.tan, 0x17 for the dictation service", sub: "Each weekday at 08:00, Radiology PC, no record, owner unknown", bad: true, why: "The shape is calm, but calm isn't a record. Nobody can vouch for it yet, so ask IT before it closes." },
          { id: "t7", text: "svc_liftctl, 0x17 for HTTP/lift-gw.valehealth.example", sub: "Every six hours for a year, lift gateway host, vendor letter on file", bad: false, why: "Four calm answers. The account stays on the remediation list." },
          { id: "t8", text: "svc_coldchain, 0x17 for the vaccine fridge monitor", sub: "Hourly since 2023, monitor host 10.30.11.22, CHG-37702 on file", bad: false, why: "Odd-sounding, but narrow, steady, and documented. A scary name isn't a signal." },
          { id: "t9", text: "svc_hl7bridge, 0x17 for svc_labint", sub: "Every 15 minutes since 2024, interface engine host, CHG-36650 on file", bad: false, why: "A service asking for another service, on a steady beat, from where it lives, with a record." },
          { id: "t10", text: "a.ioannou, 0x17 for three services", sub: "Within 40 seconds at 01:20, a Facilities PC, none of them Facilities systems", bad: true, why: "Only three, but small sweeps are still sweeps. No reason, no rhythm and no record." },
        ],
        lesson: "RC4 asks the question, and spread, rhythm, source and record answer it. If all four are calm, the rule did its job and the ticket is expected: close it citing the record and keep the account on the remediation backlog. That isn't a false positive, and calling it one invites someone to loosen a rule you need. If any one is off, keep going.",
      },
    ],
  },
};
