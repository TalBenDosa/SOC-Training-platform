import type { RoomExperience } from "./types";

// "Operation Open Sesame" for the "web-attacks-practice" room.
// Script: docs/campaign/52-web-attacks-practice.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Sundial Tickets (fictional), not the graded tasks' Orbitline records.
// Signature mechanic: intercept (hold the box office against live requests).
// Game mix: codebreak + intercept + deduce.
// Lab data differs from the graded tasks: no response sizes or baselines (q1, la1),
// no UNION payloads (la1), no load balancer or client IP question (r2 checkpoint,
// la2, f1), no scanners or change records (q2, ac1), and no w3wp or child-process
// data (o1, qf1). The deduce teaches WAF count mode, which no graded task covers.
export const WEB_ATTACKS_PRACTICE: RoomExperience = {
  roomId: "web-attacks-practice",
  codename: "Operation Open Sesame",
  theme: "webops",
  handler: { name: "Rafael Quintero", role: "Application Security Analyst, Sundial Tickets" },
  briefing: [
    "Sundial Tickets. Concerts, trains and football, 9 million bookings a year, and one website that has to stay up the moment a big tour goes on sale.",
    "Every web attack leaves two sets of footprints: what the firewall in front decided, and what the server behind it actually did. Most analysts only read one.",
    "Rafael Quintero's rule is short: a payload in a log is an attempt, and an attempt isn't a breach until something else says so.",
    "Learn to read an access log, hold the front door, join two records of one request, then follow a real case from the first probe to a shell.",
  ],
  mission: "Crack the log's status codes, hold the box office against live requests, join WAF and server records to find what slipped through, then work the graded injection case to the end.",
  estimate: "~45 min",
  look: { primary: "#fb923c", secondary: "#a3e635", warn: "#f43f5e" },
  scene: "opensesame",
  layout: "stage",
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
    // ── Reading 1: signature mechanic plus the fields ──
    "web-r1": [
      {
        kind: "codebreak",
        title: "Crack the Log",
        prompt: "Rafael won't hand you a Sundial log until you can read one. Each clue describes a part of an IIS log line. Crack the code.",
        tries: 5,
        rounds: [
          { id: "ok", clue: "The status code when the server processed a request end to end", answer: "200", why: "Success means the server finished the job, whatever the job was. It says nothing about whether the request was innocent. A lone 200 among errors proves little until you compare its response size (sc-bytes) with the endpoint's normal size: a payload that really pulled data out returns a far bigger response than an ordinary page." },
          { id: "block", clue: "The status code you usually see when a WAF or the server refuses a request", answer: "403", why: "Forbidden: understood and refused. Blocked attempts live here." },
          { id: "miss", clue: "The status code a content-discovery sweep produces most of", answer: "404", why: "Guessing paths means mostly missing them. A wall of 404s from one source is someone looking around." },
          { id: "broke", clue: "The status code when the application itself failed while handling the request", answer: "500", why: "Unlike a 4xx, the request got in and broke something on the way through." },
        ],
        lesson: "Read a status code as what the server did, never as what the client wanted. A blocked attack and a mistyped URL can share a code, and so can a success and a compromise.",
      },
      {
        kind: "intercept",
        title: "Hold the Box Office",
        prompt: "A big tour goes on sale in ten minutes, and Rafael's rule set is down. You're the WAF. Block what's hostile, but every real fan you turn away is a lost sale.",
        protect: "the booking API",
        blockLabel: "Block",
        passLabel: "Let through",
        seconds: 11,
        items: [
          { id: "obrien", text: "GET /search?name=O'Brien", sub: "single quote, real surname", bad: false, why: "An apostrophe alone isn't an attack. Blocking every quote locks out the O'Briens." },
          { id: "trav", text: "GET /files?doc=../../web.config", sub: "climbing out of the folder", bad: true, why: "Path traversal: nothing a ticket buyer does needs ../ in a parameter." },
          { id: "or", text: "GET /login?user=admin'--", sub: "comment cuts the query short", bad: true, why: "The quote and comment try to end the SQL statement early and skip the password check." },
          { id: "seat", text: "POST /basket {\"seat\":\"B-14\",\"qty\":2}", sub: "normal JSON order", bad: false, why: "Exactly what the API is for." },
          { id: "script", text: "GET /review?text=<script src=//x.example/a.js>", sub: "tag in a text field", bad: true, why: "Stored XSS attempt: a review has no reason to load a script from elsewhere." },
          { id: "html", text: "GET /search?q=Tickets+%26+Hotels", sub: "encoded ampersand", bad: false, why: "Encoded punctuation is how browsers send normal text." },
          { id: "select", text: "GET /search?q=select+seats+front+row", sub: "contains the word select", bad: false, why: "Keyword-only rules trip on this. It's English, not SQL." },
          { id: "cmd", text: "GET /pdf?ticket=1234;cat+/etc/passwd", sub: "semicolon then a command", bad: true, why: "Command injection: the semicolon tries to start a second command on the server." },
          { id: "php", text: "GET /wp-admin/setup-config.php", sub: "site isn't WordPress", bad: true, why: "Sundial doesn't run WordPress. This is a bot trying a known path on everyone." },
          { id: "qty", text: "POST /basket {\"seat\":\"B-14\",\"qty\":-2}", sub: "negative quantity", bad: true, why: "A logic attack with no special characters at all: signature rules miss these, and a negative total should never reach checkout." },
        ],
        lesson: "A payload is a shape, not a verdict. Good calls read what the field is for: a quote in a name is fine, and a perfectly clean number can still be an attack.",
      },
    ],
    // ── Reading 2: two records ──
    "web-r2": [
      {
        kind: "deduce",
        title: "What Slipped Through?",
        prompt: "Rafael's WAF is half-way through a rollout, and new rules run in COUNT mode: they log a match and let it pass. One request matched a rule and was served anyway. Join the two records and find it.",
        nameColumn: "Request",
        columns: ["WAF action", "Rule matched", "IIS record?", "sc-status"],
        suspects: [
          { id: "a", name: "req-7711", cells: ["BLOCK", "SQLi managed", "No", "-"] },
          { id: "b", name: "req-7712", cells: ["ALLOW", "none", "Yes", "404"] },
          { id: "c", name: "req-7713", cells: ["COUNT", "XSS body", "Yes", "200"] },
          { id: "d", name: "req-7714", cells: ["ALLOW", "none", "Yes", "200"] },
          { id: "e", name: "req-7715", cells: ["BLOCK", "Rate limit", "No", "-"] },
          { id: "f", name: "req-7716", cells: ["COUNT", "Bad bot", "Yes", "403"] },
        ],
        clues: [
          "It matched a WAF rule.",
          "It reached the web server: there's an IIS record for it.",
          "The application served it successfully.",
        ],
        culprit: "c",
        why: "req-7713 matched the XSS rule, but COUNT only logs. The IIS record shows the server answered 200. A blocked request never gets an IIS record, so the WAF tells you it was seen, and only the server tells you it landed. One join trap to remember: Sundial's staging nginx sits behind a reverse proxy, which opens its own TCP connection, so nginx's remote_addr is the proxy for every visitor. The visitor's address survives only in the X-Forwarded-For header the proxy adds, and only if nginx is told to log it.",
      },
    ],
    // ── Web shell station: what the ordering and the detection rely on ──
    "web-o1": [
      {
        kind: "codebreak",
        title: "Anatomy of a Web Shell",
        prompt: "Rafael wants the shell's moving parts named before you put its chain in order. Each clue describes one of them. Crack the code.",
        tries: 5,
        rounds: [
          { id: "ext", clue: "The file extension an attacker drops into an IIS site so the server runs it as code", answer: "aspx", why: "A web shell is just a server-side script placed where the web server will execute it, usually among the site's own assets so it blends in." },
          { id: "worker", clue: "The IIS worker process that runs the web application, and so writes the shell to disk", answer: "w3wp", why: "w3wp.exe is the process for the site's application pool. If it writes a new script file, the web application itself did it, not an administrator or a deployment tool." },
          { id: "shell", clue: "The command interpreter a web shell most often has the worker process start", answer: "cmd", why: "A web worker should serve pages, never parent a command interpreter. w3wp.exe spawning cmd.exe is the tell that the shell is in use." },
          { id: "limit", clue: "A WAF only inspects a request body up to a size limit. A larger upload is not fully inspected, so the WAF lets it ___", answer: "through", why: "That is how an oversized POST carrying a shell can pass even a well-configured WAF. The size limit is a known gap, not a verdict that the body was clean." },
        ],
        lesson: "A web shell is a script the web worker writes and then runs. The file write by w3wp.exe and the cmd.exe child of w3wp.exe are the footprints, and an oversized upload is one way past the WAF.",
      },
    ],
  },
};
