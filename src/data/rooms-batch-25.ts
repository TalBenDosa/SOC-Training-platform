/**
 * Learning Rooms — Batch 25
 *
 * web-application-security — the missing application-security foundation.
 *
 * Until now the platform jumped a learner straight from networking-protocols
 * into web-attacks-practice (batch 24), an ADVANCED room that asks them to
 * reconstruct a web attack from WAF and IIS telemetry. Nothing in between ever
 * taught them how a web application is actually built, what an HTTP request
 * carries, what a web-server access log does and does not record, or what a WAF
 * can and cannot see. This room is that foundation: request/response, the
 * client-server trust boundary, the three-tier path, the attack classes mapped
 * onto OWASP Top 10 2021, and how to read an access-log line field by field.
 *
 * It is deliberately the prerequisite that should sit in front of
 * web-attacks-practice.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// =============================================================================
// EVENTS
// =============================================================================

/**
 * Log Analysis 1 — an IIS W3C access-log line for a file-download endpoint.
 * The tells are all OBSERVED: the encoded traversal sequence in csUriQuery, a
 * 200 status (the application ANSWERED), and an scBytes value far below this
 * endpoint's normal payload size. Nothing in the record states a verdict.
 */
const larkfieldDownloadEvent: TelemetryEvent = {
  id: "evt-webapp-la1-001",
  ts: "2026-05-19T21:44:06.000Z",
  source: "siem",
  vendor: "Microsoft Sentinel",
  event_type: "http_request",
  severity: "high",
  hostname: "WEB-LKF01.larkfield.local",
  mitre_technique: "T1083",
  mitre_tactic: "Discovery",
  network: {
    url: "https://shop.larkfield.com/download.aspx",
    domain: "shop.larkfield.com",
    method: "GET",
    status: 200,
    bytes_out: 5312,
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  },
  description:
    "IIS access log (W3CIISLog) for shop.larkfield.com. One request to the product-datasheet download endpoint, taken from a run of similarly-shaped requests to the same endpoint within a four-minute window.",
  raw: {
    TimeGenerated: "2026-05-19T21:44:06.000Z",
    Computer: "WEB-LKF01.larkfield.local",
    sSiteName: "LARKFIELDSHOP",
    sComputerName: "WEB-LKF01",
    sIP: "10.44.2.30",
    csMethod: "GET",
    csUriStem: "/download.aspx",
    csUriQuery: "file=..%2f..%2f..%2fWindows%2fwin.ini",
    csUserName: "-",
    cIP: "10.44.2.7",
    csHost: "shop.larkfield.com",
    csUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    csReferer: "-",
    scStatus: "200",
    scSubStatus: "0",
    scWin32Status: "0",
    scBytes: "5312",
    csBytes: "488",
    TimeTaken: "61",
    csVersion: "HTTP/1.1",
    Type: "W3CIISLog",
  },
};

/**
 * Log Analysis 2 — the AWS WAF record for the SAME request as Log Analysis 1.
 * Teaches the two facts the WAF record carries that IIS cannot: the real client
 * IP, and whether any rule matched at all (action ALLOW, terminatingRuleId NONE).
 */
const larkfieldWafEvent: TelemetryEvent = {
  id: "evt-webapp-la2-001",
  ts: "2026-05-19T21:44:05.000Z",
  source: "waf",
  vendor: "AWS WAF",
  event_type: "waf_allow",
  severity: "high",
  hostname: "WEB-LKF01.larkfield.local",
  src_ip: "45.147.230.19",
  mitre_technique: "T1083",
  mitre_tactic: "Discovery",
  network: {
    url: "https://shop.larkfield.com/download.aspx",
    domain: "shop.larkfield.com",
    method: "GET",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  },
  description:
    "AWS WAF record for the request reviewed in Log Analysis 1, matched by URI, method and a timestamp one second apart.",
  raw: {
    formatVersion: 1,
    timestamp: 1747691045000,
    webaclId: "arn:aws:wafv2:eu-west-1:702844913065:regional/webacl/larkfield-shop-prod/9c41b7d2-05fe-4a63-8b17-2ad9e5c31f40",
    terminatingRuleId: "NONE",
    terminatingRuleType: "REGULAR",
    action: "ALLOW",
    httpSourceName: "ALB",
    httpSourceId: "app/larkfield-shop-alb/3d7f10b8c5a2e947",
    "httpRequest.clientIp": "45.147.230.19",
    "httpRequest.country": "NL",
    "httpRequest.httpMethod": "GET",
    "httpRequest.uri": "/download.aspx",
    "httpRequest.args": "file=..%2f..%2f..%2fWindows%2fwin.ini",
    "httpRequest.httpVersion": "HTTP/1.1",
    "httpRequest.requestId": "1-682b4165-7ac1e0d94f28b3560a17ce82",
    "httpRequest.headers[0].name": "Host",
    "httpRequest.headers[0].value": "shop.larkfield.com",
    "httpRequest.headers[1].name": "User-Agent",
    "httpRequest.headers[1].value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "httpRequest.headers[2].name": "Accept",
    "httpRequest.headers[2].value": "*/*",
  },
};

/**
 * Analyst Choice — a WAF BLOCK that is a genuine false positive: an ordinary
 * customer-facing search for a surname containing an apostrophe trips the
 * managed SQLi rule group. Signal stays observational; the change/helpdesk
 * context arrives through it_verify_*, not through an invented log field.
 */
const larkfieldSearchBlockEvent: TelemetryEvent = {
  id: "evt-webapp-ac1-001",
  ts: "2026-05-21T13:08:52.000Z",
  source: "waf",
  vendor: "AWS WAF",
  event_type: "waf_block",
  severity: "low",
  hostname: "WEB-LKF01.larkfield.local",
  src_ip: "198.51.100.62",
  it_verify_result: "confirmed",
  it_verify_message:
    "Helpdesk ticket HD-44127, raised the same afternoon: three staff in the Larkfield Bristol branch report that the customer-lookup page returns an error page whenever they search for a customer whose surname contains an apostrophe. 198.51.100.62 is the Bristol branch office internet egress address.",
  network: {
    url: "https://shop.larkfield.com/customers/lookup.aspx",
    domain: "shop.larkfield.com",
    method: "GET",
    status: 403,
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/135.0.0.0",
  },
  description:
    "AWS WAF blocked a request to the staff customer-lookup page. The managed SQL injection rule group was the terminating rule.",
  raw: {
    formatVersion: 1,
    timestamp: 1747832932000,
    webaclId: "arn:aws:wafv2:eu-west-1:702844913065:regional/webacl/larkfield-shop-prod/9c41b7d2-05fe-4a63-8b17-2ad9e5c31f40",
    terminatingRuleId: "AWS-AWSManagedRulesSQLiRuleSet",
    terminatingRuleType: "MANAGED_RULE_GROUP",
    action: "BLOCK",
    httpSourceName: "ALB",
    httpSourceId: "app/larkfield-shop-alb/3d7f10b8c5a2e947",
    "httpRequest.clientIp": "198.51.100.62",
    "httpRequest.country": "GB",
    "httpRequest.httpMethod": "GET",
    "httpRequest.uri": "/customers/lookup.aspx",
    "httpRequest.args": "surname=O%27Brien&branch=BRS",
    "httpRequest.httpVersion": "HTTP/1.1",
    "httpRequest.requestId": "1-682d7be4-1f60a385d92c47b80e5a1c33",
    "httpRequest.headers[0].name": "Host",
    "httpRequest.headers[0].value": "shop.larkfield.com",
    "httpRequest.headers[1].name": "User-Agent",
    "httpRequest.headers[1].value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/135.0.0.0",
    "httpRequest.headers[2].name": "Referer",
    "httpRequest.headers[2].value": "https://shop.larkfield.com/customers/lookup.aspx",
  },
};

// =============================================================================
// ROOM: web-application-security
// =============================================================================

const webApplicationSecurityRoom: Room = {
  id: "web-application-security",
  title: "How Web Applications Work — and How They Break",
  description:
    "Before you can investigate a web attack you have to know what a web request actually is. This room builds that from zero: what travels in an HTTP request and response, why nothing the browser sends can ever be trusted, the browser-to-server-to-application-to-database path every request takes, the attack classes that live at each stop mapped onto the OWASP Top 10 2021, what a WAF genuinely catches versus what it is blind to, and how to read a real IIS access-log line field by field — including the two things it never records: the request body, and the true client IP.",
  difficulty: "beginner",
  category: "Application Security",
  estimatedMinutes: 60,
  xp: 310,
  icon: "🌐",
  prerequisites: ["networking-protocols"],
  tasks: [
    // ------------------------------------------------------------------
    // Reading 1 — the request/response model and the three-tier path
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "webapp-r1",
      heading: "What Actually Happens When You Open a Web Page",
      content:
        `Typing an address into a browser feels like opening a document. It is nothing of the sort. What actually happens is a conversation: your browser writes a short, strictly-formatted message called an HTTP request, sends it across the network, and a machine on the other side writes back an HTTP response. Every web attack you will ever investigate is somebody putting something unexpected into that request, so it is worth knowing exactly what a request is made of before anything else.\n\n` +
        `**The parts of a request**\n\n` +
        `A request has a small, fixed set of parts. The METHOD is the verb — GET means give me something, POST means here is some data, take it. The PATH is which thing on the site you want, for example /download.aspx. The QUERY STRING is everything after the question mark, a list of name=value pairs the page uses as its input: ?file=datasheet.pdf&lang=en. HEADERS are lines of metadata that travel alongside — which browser you claim to be (User-Agent), which page you came from (Referer), which site name you are asking for (Host). COOKIES are a special header, a small piece of text the site gave your browser earlier and your browser hands back on every subsequent request, which is how a site remembers that you are logged in. And the BODY is the bulk payload, used mostly by POST — this is where the contents of a filled-in form actually travel.\n\n` +
        `The response comes back with a STATUS CODE, a three-digit number stating what happened (200 succeeded, 403 refused, 404 not found, 500 the server broke), its own headers, and the body — the HTML, image or file you actually wanted. Think of it as a counter at a records office: the method is whether you are collecting or dropping off, the path is which counter, the query string is what you shouted across it, the cookie is the ticket stub proving you already queued once, and the status code is the clerk telling you whether you got it.\n\n` +
        `**Where the request goes: the three-tier path**\n\n` +
        `On the other side of that request, almost no real site is one machine. The classic shape has three distinct jobs, usually on different servers. The WEB SERVER (Microsoft IIS, Apache, nginx) speaks HTTP: it accepts the connection, hands back static files like images by itself, writes the access log, and passes anything that needs thinking about to the next tier. The APPLICATION is the actual code somebody at the company wrote — .NET, Java, PHP, Python — and it is the tier that takes those name=value pairs from the query string and decides what to do with them. The DATABASE stores the data and executes whatever query the application hands it. It does not know or care where that query came from.\n\n` +
        `That handoff chain is the whole game. The web server trusts the request enough to pass it on, the application trusts the parameters enough to build a query from them, and the database trusts the query enough to run it. Every single attack class in this room is a case of one of those tiers trusting the previous one a little more than it should have. Hold that sentence — the rest of the room is a tour of exactly where it goes wrong.`,
      diagram:
        "flowchart LR\n" +
        '  B["1. Browser - the client. Method, path, query string, headers, cookies, body"] --> S["2. Web server - IIS, Apache, nginx. Speaks HTTP, writes the access log"]\n' +
        '  S --> A["3. Application - the code the company wrote. Turns parameters into actions"]\n' +
        '  A --> D["4. Database - executes whatever query the application hands it"]\n' +
        '  D -.->|"rows"| A\n' +
        '  A -.->|"generated page"| S\n' +
        '  S -.->|"status code plus response body"| B',
      diagramCaption: "The three-tier path every web request takes, and the return journey",
    },

    // ------------------------------------------------------------------
    // Reading 2 — the trust boundary
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "webapp-r2",
      heading: "The Trust Boundary: Nothing the Browser Sends Is Yours",
      content:
        `Here is the single most important idea in application security, and it is one sentence long: everything in the request is under the attacker's control. Not most of it. All of it. The method, the path, every query-string parameter, every header, every cookie, and the entire body. If it arrived over the network, somebody on the other end chose what it says, and that somebody may not be using a browser at all.\n\n` +
        `**Why beginners get this wrong**\n\n` +
        `The confusion comes from watching a normal user's experience and mistaking it for a constraint. A user visits a page, sees a form with a dropdown offering three options, picks one, and clicks submit. It feels as though only those three values can ever arrive at the server. They cannot be enforced that way. The dropdown is HTML the server sent to the browser as a suggestion; the request the browser sends back is just text, and any tool that speaks HTTP — a proxy sitting between browser and server, a command-line utility, a twenty-line script — can send that same request with any value at all in that field. The lock on the form is drawn on the outside of the door.\n\n` +
        `The three cases worth naming specifically. HIDDEN FORM FIELDS are fields the page includes but does not display, often carrying things like a price or an item ID; they are hidden from the user's eyes, not from the request, and they arrive at the server as ordinary editable text. COOKIES feel safe because the server issued them, but they live on the client's machine between requests and come back modified as easily as unmodified — a cookie reading role=user can come back reading role=admin, and if the application believes it, that is a real, exploited vulnerability. JAVASCRIPT VALIDATION is the checking code that runs in the browser and turns a field red when you type a letter into a phone-number box; it is genuinely useful, because it stops honest users making honest mistakes before they waste a round trip. It is worth nothing as security, because it runs on the attacker's computer, and anyone can simply not run it.\n\n` +
        `**The rule an analyst carries from this**\n\n` +
        `The rule developers learn is: validate on the server, every time, no exceptions, because that is the first machine in the chain the attacker does not control. The rule an ANALYST takes away is subtly different but just as useful. When you look at a log line and something in it seems impossible — a parameter with a value no dropdown offered, a Content-Length far larger than any form on that page could produce, a User-Agent claiming to be a browser on a request no browser would ever generate — do not talk yourself out of it. Do not assume the field is corrupt or the log is wrong. Assume somebody sent exactly that on purpose, because the request format allows them to, and ask what they were trying to achieve by sending it.\n\n` +
        `This is also why User-Agent is never proof of anything. It is a header the client writes. A scanner announcing itself as a scanner is telling you the truth voluntarily, which is useful; an attacker claiming to be Chrome is telling you what they want you to believe, which is a claim, not evidence. Treat honest-looking headers as weak corroboration and never as identification.`,
      codeExample:
        "THE CLIENT-SERVER TRUST BOUNDARY\n" +
        "=======================================================\n" +
        "EVERYTHING BELOW IS ATTACKER-CONTROLLED:\n" +
        "  method       GET / POST / PUT / anything\n" +
        "  path         /download.aspx\n" +
        "  query string ?file=... &id=... &price=...\n" +
        "  headers      User-Agent, Referer, Host, X-Forwarded-For\n" +
        "  cookies      session=..., role=..., cart_total=...\n" +
        "  body         the entire POST payload\n" +
        "=======================================================\n\n" +
        "THREE THINGS THAT ARE NOT SECURITY CONTROLS\n" +
        "=======================================================\n" +
        "Hidden form field   Hidden from the eye, not the request.\n" +
        "                    Arrives as ordinary editable text.\n" +
        "Cookie value        Stored on the CLIENT between requests.\n" +
        "                    role=user can come back role=admin.\n" +
        "JavaScript check    Runs on the attacker's own machine.\n" +
        "                    Good UX. Zero security value.\n" +
        "=======================================================\n\n" +
        "ANALYST TAKEAWAY\n" +
        "=======================================================\n" +
        "A value that 'could not have been sent by the page'\n" +
        "was not a glitch -- it was sent deliberately, by\n" +
        "something that was not the page.\n" +
        "=======================================================",
    },

    // ------------------------------------------------------------------
    // Question 1 — the POST body blind spot
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "webapp-q1",
      question:
        "An attacker sends a SQL injection payload in the BODY of a POST request to /login.aspx. You open the IIS access log for that exact second. What do you see?",
      options: [
        "The full payload in csUriQuery, since IIS records every parameter a request carries regardless of method",
        "A csMethod of POST, a csUriStem of /login.aspx and a csUriQuery of '-' — the payload itself does not appear anywhere, because a W3C access log records the request line and selected headers, never the request body",
        "Nothing at all, because IIS does not create access-log entries for POST requests",
        "The payload appears, but only in the scBytes field, encoded as its byte length",
      ],
      answer: 1,
      explanation:
        "A W3C access log line records the request line and a selection of headers — method, URI stem, query string, client IP, User-Agent, status, byte counts — and the request body is not among them, so a POST-delivered payload leaves a line that looks completely ordinary. IIS absolutely does log POST requests, they just look unremarkable; csUriQuery holds only the query string, which a POST typically leaves empty; and scBytes is the size of the RESPONSE the server sent back, not an encoding of the request payload. This is why POST-based attacks are nearly invisible in web-server logs alone and why you need WAF logs, application logs, or database audit logs to see them.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Reading 3 — the attack classes and where they land
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "webapp-r3",
      heading: "The Attack Classes, and Where Each One Lands on the Path",
      content:
        `Now put Reading 1's three-tier path together with Reading 2's rule that everything from the client is hostile, and the attack classes almost derive themselves. Each one is untrusted input reaching a tier that treats it as instruction rather than as data. What changes between them is WHICH tier gets fooled, and therefore which log holds the evidence. The category names below are the OWASP Top 10 2021, the industry's standard list of the ten most critical web application security risks — knowing which bucket an attack falls into is how you talk to a developer about it.\n\n` +
        `**SQL INJECTION** (OWASP A03:2021 Injection, ATT&CK T1190). One sentence: untrusted input reaches a database query and changes its meaning. The application glues a parameter into a query string, and a value carrying its own quote characters and SQL keywords turns one query into two. The log tell lives in the parameter — quote characters, UNION, SELECT, OR 1=1 — and, crucially, in the OUTCOME: a burst of 500 errors is malformed syntax crashing the query parser, whereas a 200 with a response size unlike anything that endpoint normally returns is a query that actually ran.\n\n` +
        `**CROSS-SITE SCRIPTING, XSS** (A03:2021 Injection, ATT&CK T1059.007). One sentence: untrusted input is written back into a page, and the victim's browser executes it as script. REFLECTED XSS bounces off a single response: the payload is in the link, so the attacker has to get each victim to click a crafted URL, and the damage is one victim at a time. STORED XSS is put into the application's own data — a comment, a profile field, a support-ticket subject — and served to every user who later views that page, with no link to click and no action required from the victim. That is why stored is far worse: reflected needs a lure per victim, stored fires automatically at everyone, including the administrator who opens the ticket queue. The tell for reflected is script-shaped text in a query parameter; the tell for stored is often a single POST that looks like nothing, followed later by the payload appearing in ordinary responses to entirely different users.\n\n` +
        `**PATH TRAVERSAL / LOCAL FILE INCLUSION** (A01:2021 Broken Access Control, ATT&CK T1083). One sentence: a parameter that names a file is given a value that climbs out of the intended folder. The tell is dot-dot-slash sequences, plain or URL-encoded as %2e%2e%2f or ..%2f, in a parameter whose name suggests a file, page, template or path — and again, a 200 response with a size unlike the endpoint's normal payload means something got read and returned.\n\n` +
        `**COMMAND INJECTION and REMOTE CODE EXECUTION** (A03:2021 Injection, ATT&CK T1059). One sentence: untrusted input reaches something that runs operating-system commands, so the input becomes a command. The tell in the web log is shell metacharacters — semicolon, pipe, backtick-style substitution, ampersand — in a parameter. The confirmation is not in the web log at all: it is on the endpoint, where the web server's own worker process (w3wp.exe on IIS) becomes the parent of cmd.exe or a scripting host, something a web worker has no legitimate reason to do.\n\n` +
        `**AUTHENTICATION AND SESSION FLAWS** (A07:2021 Identification and Authentication Failures). Because HTTP has no memory, the session cookie IS your identity for the whole visit — steal it and you are that user without ever knowing their password. SESSION FIXATION is an attacker planting a session identifier they already know into the victim's browser before login, and the application failing to issue a fresh one when the victim actually authenticates, so the attacker's known value silently becomes an authenticated session. WEAK SESSION TOKENS are identifiers that are short, sequential or predictable, letting an attacker guess a live one outright. The tell is a single session identifier appearing from two different client IP addresses at once, or a run of near-identical token values being tried.\n\n` +
        `**INSECURE DIRECT OBJECT REFERENCE, IDOR / BROKEN ACCESS CONTROL** (A01:2021 Broken Access Control). One sentence: a logged-in user changes an identifier in a URL and receives somebody else's data, because the application checked that you are logged in but never checked that this particular record is yours. Read the tell carefully, because it is the most important thing in this reading: there is no payload. The request /invoice.aspx?id=88413 is perfectly well-formed, contains no quote, no dot-dot-slash, no script tag, no metacharacter, and is byte-for-byte the shape of a legitimate request — the only thing wrong with it is who sent it. No signature can match it, and it will not appear in any WAF log as anything other than ordinary allowed traffic. The only way it is ever caught is behavioural: one account walking sequentially through many identifiers, or accessing records it has no business relationship with.`,
      diagram:
        "flowchart TD\n" +
        '  B["Browser"] --> W["WAF"]\n' +
        '  W --> S["Web server"]\n' +
        '  S --> A["Application"]\n' +
        '  A --> D["Database"]\n' +
        '  W -.- X1["Catches what it can pattern-match: SQLi, XSS, traversal, command injection signatures"]\n' +
        '  S -.- X2["Path traversal resolves here - the file read happens on the web server filesystem"]\n' +
        '  A -.- X3["XSS, command injection, session flaws and IDOR all live in application logic"]\n' +
        '  D -.- X4["SQL injection finally executes here - and the DB audit log is where you confirm it"]',
      diagramCaption: "Which tier each attack class actually lands on — and therefore which log holds the proof",
    },

    // ------------------------------------------------------------------
    // Matching — attack class to its log tell
    // ------------------------------------------------------------------
    {
      type: "matching",
      id: "webapp-m1",
      heading: "Match Each Attack Class to the Evidence It Actually Leaves",
      instructions:
        "Match each web attack class to the observable tell that would let you recognise it in telemetry.",
      pairs: [
        {
          id: "sqli",
          left: "SQL injection (A03:2021 Injection, T1190)",
          right: "Quote characters and SQL keywords in a parameter, a run of 500 errors from malformed syntax, and the one 200 whose response size is wildly unlike the endpoint's normal output",
        },
        {
          id: "storedxss",
          left: "Stored cross-site scripting (A03:2021 Injection, T1059.007)",
          right: "A single unremarkable POST that saves script-shaped text into the application's own data, followed later by that text being served back inside normal responses to other, unrelated users",
        },
        {
          id: "traversal",
          left: "Path traversal / local file inclusion (A01:2021 Broken Access Control, T1083)",
          right: "Dot-dot-slash sequences, plain or URL-encoded, in a parameter that names a file, page or template, returning a 200 whose byte count does not match the endpoint's usual payload",
        },
        {
          id: "cmdinj",
          left: "Command injection / remote code execution (A03:2021 Injection, T1059)",
          right: "Shell metacharacters in a parameter in the web log, confirmed on the endpoint by the web server's worker process becoming the parent of a command interpreter or scripting host",
        },
        {
          id: "session",
          left: "Session fixation and weak session tokens (A07:2021 Identification and Authentication Failures)",
          right: "One session identifier presented from two different client addresses in the same window, or a sequence of near-identical token values being submitted in turn",
        },
        {
          id: "idor",
          left: "Insecure direct object reference (A01:2021 Broken Access Control)",
          right: "Nothing anomalous in any single request — every one is perfectly well-formed with no payload at all; only the behavioural pattern of one account walking through many record identifiers reveals it",
        },
      ],
      explanation:
        "Each tell follows directly from where the attack lands on the three-tier path. SQL injection ends at the database, so its evidence is split between the parameter that carried it and the response outcome that shows whether the query ran. Stored XSS is uniquely two-part — an innocuous-looking write, then a delayed read by somebody else — which is exactly why it is worse than reflected XSS and harder to spot. Path traversal resolves against the web server's own filesystem, so the response size gives it away. Command injection's real proof is never in the web log at all; it is the parent-child process relationship on the endpoint. Session flaws show up as one identity appearing in two places at once. And IDOR is the one with no signature whatsoever: every request is textbook-legal, which is precisely why a WAF cannot see it and why only behaviour betrays it.",
      xp: 40,
    },

    // ------------------------------------------------------------------
    // Log Analysis 1 — reading an IIS line field by field
    // ------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "webapp-la1",
      heading: "Reading an IIS Access-Log Line, Field by Field",
      context:
        "Larkfield's online shop has a datasheet download page at /download.aspx, which takes a file parameter and returns the requested product PDF. Normal responses from this endpoint run between 240,000 and 900,000 bytes. Over four minutes on 19 May, this endpoint received 31 requests from the same session, each carrying a different value in the file parameter. The record below is one of them. Work through the fields one at a time.",
      event: larkfieldDownloadEvent,
      questions: [
        {
          question:
            "Start with the request itself. csMethod is GET, csUriStem is /download.aspx and csUriQuery is 'file=..%2f..%2f..%2fWindows%2fwin.ini'. What is the client asking for, once you decode it?",
          options: [
            "A product datasheet named win.ini stored in the site's normal download folder",
            "A file path that uses URL-encoded dot-dot-slash sequences (%2f is a forward slash) to climb three folders up out of the intended download directory and reach a file elsewhere on the server's filesystem",
            "Nothing meaningful — %2f is not a valid encoding and the server would reject this parameter outright",
            "A second web page to be loaded inside the first, which is standard behaviour for any page that takes a file parameter",
          ],
          answer: 1,
          explanation:
            "%2f is simply the URL encoding of a forward slash, so the decoded value reads ../../../Windows/win.ini — three dot-dot-slash steps climbing out of whatever folder the application intended, then a path to somewhere else entirely on the server. That is the classic path traversal shape from Reading 3, and encoding it is a routine way of getting past naive filters that only look for literal dot-dot-slash text. It is not a datasheet, %2f is a completely valid and extremely common encoding, and loading arbitrary filesystem paths is not standard behaviour for anything.",
          xp: 25,
        },
        {
          question:
            "Now read the outcome fields. scStatus is 200 and scBytes is 5,312, against this endpoint's normal range of 240,000 to 900,000 bytes. Why is this pairing more serious than the same request returning 403?",
          options: [
            "It is not more serious — 200 simply confirms the web server received the request, while 403 would mean it never arrived at all",
            "A 403 would mean the request was refused before the application did anything; a 200 means the application ANSWERED, and a byte count nowhere near this endpoint's normal PDF size is consistent with it having returned a small text file rather than a datasheet",
            "A 200 status on a download endpoint always means a cached response was served, so nothing was actually read from disk",
            "scBytes counts the size of the request, so a small value proves the payload was truncated before it could do anything",
          ],
          answer: 1,
          explanation:
            "This is the single most important reading skill in the room: status code is OUTCOME, not intent. A 403 means something in the chain refused the request and the application never acted on it — an attempt, and a blocked one. A 200 means the request went all the way through and the server returned a body, so the question stops being whether it was tried and becomes what was returned. The byte count settles that: 5,312 bytes is nowhere near a product PDF, but is entirely consistent with a small system text file. A 200 does not imply caching, and scBytes is the size of the RESPONSE the server sent, not the request.",
          xp: 25,
        },
        {
          question:
            "One more field before you escalate. cIP shows 10.44.2.7 — a private, internal address, even though shop.larkfield.com is a public internet-facing site. What should you conclude?",
          options: [
            "The attack came from inside the network, so start the investigation on the internal host at 10.44.2.7",
            "The public site sits behind a load balancer, which opened its own connection to the web server — so cIP is the load balancer's internal address, not the real client, and the true source has to come from an upstream log such as the WAF's",
            "The cIP field was corrupted during log ingestion and should be ignored entirely",
            "A private address in cIP proves the request never actually reached the application, since internal addresses cannot route to public sites",
          ],
          answer: 1,
          explanation:
            "A private RFC1918 address in the client-IP field of a public-facing site is the signature of a proxied architecture, not an insider: the load balancer terminates the client's connection and opens a fresh one to the web server using its own address, so IIS faithfully logs the machine it is actually talking to. Chasing 10.44.2.7 as the attacker would send you to investigate your own load balancer, which is exactly the wrong-host mistake this room exists to prevent. The field is not corrupt — it is accurate and simply answers a different question than the one you asked — and the 200 status already proves the request very much reached the application.",
          xp: 30,
        },
      ],
    },

    // ------------------------------------------------------------------
    // Reading 4 — the WAF
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "webapp-r4",
      heading: "The WAF: What It Sees, What It Misses, and the X-Forwarded-For Problem",
      content:
        `A WAF — Web Application Firewall — sits in front of the application and inspects HTTP requests before they reach it. That is a different job from an ordinary network firewall, which decides whether a connection to a port is allowed at all. The network firewall says port 443 is open to the world; the WAF is the one reading what is being said through it. If a network firewall is a door policy, the WAF is the person at the door actually listening to what you are asking for and deciding whether to let it through.\n\n` +
        `**How it decides**\n\n` +
        `Two mechanisms, working together. SIGNATURE MATCHING compares the request against a catalogue of known-bad patterns — SQL keywords in odd places, script tags in parameters, dot-dot-slash sequences, shell metacharacters. Cloud WAFs ship these as managed rule groups, and when a request trips one, the log records which rule ended the evaluation (in AWS WAF, terminatingRuleId) and what was done about it (action: BLOCK or ALLOW). ANOMALY SCORING adds up smaller oddities — an unusually long parameter, an unusual character mix, too many parameters — and blocks once the total crosses a threshold, catching things no single signature would. The critical field to read in any WAF log is therefore the action, and the second most critical is whether any rule matched at all: an ALLOW with a terminating rule of NONE means no rule even fired, which is a very different statement from a rule firing and deciding the request was acceptable.\n\n` +
        `**What it genuinely cannot catch**\n\n` +
        `First and most important: BUSINESS LOGIC ABUSE. A WAF matches patterns in a request; IDOR from Reading 3 has no pattern. The request /invoice.aspx?id=88413 is textbook-legal, and whether it is theft depends entirely on whether the person sending it owns invoice 88413 — a fact about your application's data that the WAF has no access to and no way to learn. Every rule in every managed rule group will pass that request, correctly, and the attack will still succeed. The same applies to a coupon applied a thousand times, a password reset requested for someone else's account, or a workflow step skipped. Second: ENCRYPTED-THEN-TERMINATED-ELSEWHERE traffic. A WAF can only inspect what it can read, and HTTPS is encrypted end to end unless something decrypts it. If TLS terminates somewhere the WAF is not — a different load balancer, a separate ingress, an API gateway on another path — then the WAF sees ciphertext or never sees the request at all, and whole routes into the application can bypass it entirely. Third: anything the WAF was configured not to inspect, most commonly request bodies over a size limit, which is exactly how oversized malicious uploads slip past a correctly-working WAF.\n\n` +
        `**The X-Forwarded-For problem, plainly**\n\n` +
        `This one field causes more wasted investigations than any other in web analysis, and Log Analysis 1 already walked you into it. When a request passes through a load balancer, the load balancer does not forward packets — it terminates the client's connection and opens a brand new one to the backend web server, using its own address as the source. From the web server's point of view, the load balancer IS the client, and it logs the load balancer's internal IP faithfully and correctly in cIP, for every request, forever.\n\n` +
        `To stop the real address being lost, the proxy copies it into a header called X-Forwarded-For before passing the request along. So on a proxied site the real client IP is not in the client-IP field at all — it is sitting in a header, and only if the web server was configured to record that header will it appear in the access log at all. Two consequences you must carry with you. One: if you investigate the address in cIP on a proxied site, you will investigate your own infrastructure, every time. Two: X-Forwarded-For is a header, which by Reading 2's rule means the client can write anything they like into it — so it can only be trusted for the hops you control, and a value in it should never be blocked on blindly. The address that IS reliable is the one recorded by the WAF or the edge proxy itself, because that component saw the real TCP connection with its own eyes rather than being told about it.`,
      codeExample:
        "WAF: THE FOUR QUESTIONS TO ASK OF ANY WAF RECORD\n" +
        "=======================================================\n" +
        "1. action            BLOCK  -> request never reached the app\n" +
        "                     ALLOW  -> the app processed it\n" +
        "2. terminatingRuleId which rule ended evaluation?\n" +
        "                     NONE   -> no rule fired AT ALL\n" +
        "3. clientIp          the real source -- the WAF saw the\n" +
        "                     actual connection, unlike the web server\n" +
        "4. uri + args        what was actually asked for\n" +
        "=======================================================\n\n" +
        "WHAT A WAF CANNOT CATCH\n" +
        "=======================================================\n" +
        "Business logic abuse   IDOR, coupon replay, skipped steps.\n" +
        "                       No pattern exists to match.\n" +
        "TLS terminated         If it cannot decrypt it, it cannot\n" +
        "  somewhere else       read it. Bypass routes stay invisible.\n" +
        "Oversized bodies       Inspection size limits are how large\n" +
        "                       malicious uploads slip past.\n" +
        "=======================================================\n\n" +
        "THE X-FORWARDED-FOR PROBLEM\n" +
        "=======================================================\n" +
        "Web server cIP    = the LOAD BALANCER, every single request\n" +
        "X-Forwarded-For   = the real client -- but it is a HEADER,\n" +
        "                    so the client can forge it\n" +
        "WAF clientIp      = trustworthy: the WAF saw the real\n" +
        "                    TCP connection itself\n" +
        "=======================================================",
    },

    // ------------------------------------------------------------------
    // Question 2 — the WAF's blind spot
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "webapp-q2",
      question:
        "A customer logs into Larkfield's portal legitimately, then edits the URL /invoice.aspx?id=88412 to id=88413 and receives another customer's invoice with a 200 response. The WAF logged the request with action ALLOW and terminatingRuleId NONE. Why did the WAF not stop it?",
      options: [
        "The WAF's managed rule groups were disabled, and enabling them would catch this request",
        "The request is perfectly well-formed with no malicious pattern to match — whether it is theft depends on whether that customer owns invoice 88413, a fact about the application's data the WAF has no access to",
        "The WAF ignores any request that carries a valid session cookie, treating authenticated traffic as trusted by default",
        "A WAF only inspects POST bodies, so GET requests with query strings pass through uninspected",
      ],
      answer: 1,
      explanation:
        "This is broken access control (OWASP A01:2021), and it is the canonical example of what a pattern-matching control structurally cannot see: there is no payload, no quote, no dot-dot-slash, nothing anomalous in the request at all — it is byte-for-byte the shape of a legitimate one, and the only thing wrong is who sent it. No rule group would help, because there is nothing to match on; WAFs do not exempt authenticated traffic from inspection; and WAFs inspect query strings routinely, which is exactly how they catch SQL injection in GET parameters. The only thing that catches IDOR is behavioural analysis — one account walking through many record identifiers — or, properly, an authorisation check in the application itself.",
      xp: 25,
    },

    // ------------------------------------------------------------------
    // Log Analysis 2 — the WAF record for the same request
    // ------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "webapp-la2",
      heading: "The Same Request, Seen From the WAF",
      context:
        "You could not identify the real source of the /download.aspx request from the IIS record, because cIP showed the load balancer. Below is the AWS WAF record for that same request, matched by URI, method, and a timestamp one second earlier. Read what this record can tell you that the IIS record could not.",
      event: larkfieldWafEvent,
      questions: [
        {
          question:
            "httpRequest.clientIp here is 45.147.230.19, while cIP on the IIS record for the same request was 10.44.2.7. Which address should the investigation follow, and why do the two records disagree?",
          options: [
            "10.44.2.7, because the web server sits closer to the application and therefore has the more accurate view of the request",
            "45.147.230.19 — the WAF sits at the edge and saw the real client connection, whereas the load balancer opened a separate connection to IIS using its own address, which is what IIS correctly recorded",
            "Neither can be trusted, since a single request cannot legitimately produce two different source addresses in two logs",
            "Both are equally valid views of the same external client, simply recorded in different notations by two vendors",
          ],
          answer: 1,
          explanation:
            "The two records disagree because they are describing two different TCP connections that together carry one logical request: the client-to-WAF connection, where the real source is visible, and the load-balancer-to-IIS connection, where the source is the load balancer itself. Neither log is wrong, and neither is closer to the truth by virtue of being nearer the application — proximity to the app is exactly what destroys source visibility here. Following 10.44.2.7 would mean investigating Larkfield's own load balancer while the real actor at 45.147.230.19 continues unbothered.",
          xp: 25,
        },
        {
          question:
            "action is ALLOW and terminatingRuleId is NONE. What does that combination actually mean, and what does it tell you about how much protection the WAF provided here?",
          options: [
            "A rule evaluated the request, judged it safe and explicitly permitted it, so the WAF has confirmed this traffic is benign",
            "No rule fired at all — the encoded traversal sequence did not match any signature in the deployed rule set, so the request passed straight through to the application, which then answered it with a 200",
            "ALLOW with no terminating rule means the request was logged but never actually forwarded to the backend",
            "terminatingRuleId NONE indicates a WAF configuration error, and the record should be discarded as unreliable",
          ],
          answer: 1,
          explanation:
            "This is the distinction Reading 4 flagged: a terminating rule of NONE means evaluation ran to the end without anything matching, which is a statement about the rule set's coverage, not a clean bill of health for the request. Combined with the IIS record's 200 and its anomalous byte count, it says plainly that a traversal attempt reached the application and got an answer. A WAF never certifies traffic as benign; ALLOW means the request was forwarded, not withheld; and NONE is an entirely normal, correctly-emitted value that appears on the overwhelming majority of ordinary traffic.",
          xp: 25,
        },
        {
          question:
            "You now have a confirmed source and confirmed evidence the application answered. What is the right next step?",
          options: [
            "Add a deny rule for 45.147.230.19 in the web server's own configuration, since that is where the request was finally processed",
            "Block 45.147.230.19 at the WAF — the only component in the path that can actually match on that address — then search WAF logs for that same clientIp across the wider window to scope everything else it touched, and get the download endpoint's file parameter fixed",
            "Take no action, since the WAF has already recorded the request and the record is available for later review",
            "Block 10.44.2.7 at the perimeter, since that is the address the web server itself recorded for the request",
          ],
          answer: 1,
          explanation:
            "Blocking has to happen where the real address is actually visible, and that is the WAF — the web server never sees 45.147.230.19 at all, so a deny rule there would have nothing to match against. Scoping matters just as much as blocking: the same clientIp field is your pivot for finding every other request this actor made, and none of that is a substitute for fixing the underlying parameter handling, since a source-IP block is trivially defeated by moving to another address. Logging a request is not responding to one, and blocking 10.44.2.7 would sever Larkfield's own load balancer and take the whole site offline for everyone.",
          xp: 30,
        },
      ],
    },

    // ------------------------------------------------------------------
    // Analyst choice — a WAF false positive
    // ------------------------------------------------------------------
    {
      type: "analyst_choice",
      id: "webapp-ac1",
      heading: "Verdict: A Blocked Request That Tripped the SQL Injection Rule Group",
      scenario:
        "Two days later, AWS WAF blocked a request to Larkfield's internal customer-lookup page. The terminating rule was the managed SQL injection rule group — the same rule category that catches real attacks. Review the record and the attached helpdesk context, then give your verdict.",
      event: larkfieldSearchBlockEvent,
      correct_verdict: "false_positive",
      explanation:
        "Decode the argument string and the picture resolves: surname=O%27Brien is simply the surname O'Brien, where %27 is the URL encoding of an apostrophe. An apostrophe is the exact character SQL injection uses to break out of a string literal, so a signature scanning for it in a parameter fires on a genuine Irish surname just as readily as on a payload — and there is no second SQL keyword, no UNION, no comment marker, no OR 1=1 anywhere in the request. Everything else corroborates the mundane reading: the source is the Bristol branch office egress address rather than an unfamiliar external one, the Referer shows the request came from the lookup page itself rather than being crafted externally, the branch parameter carries an ordinary value, and a helpdesk ticket raised the same afternoon describes staff hitting an error page on exactly this search. The correct outcome is not an escalation but a rule tuning request, because until it is fixed, staff cannot serve any customer whose surname contains an apostrophe.",
      fp_trap:
        "Everything about the surface of this record argues for escalation: a BLOCK action, the SQL injection managed rule group as the terminating rule, and an encoded quote character sitting in a parameter — which is genuinely the first thing real SQL injection looks like. The habit that saves you is decoding the argument string and asking what the value would mean if it were innocent, before asking what it would mean if it were hostile. Real injection needs more than a quote: it needs SQL that does something once the quote has broken out of the string, and none is present here. Escalating every SQLi-signature block without decoding the parameter and checking the source and the Referer is how analysts spend a day on a customer surname — and, worse, how a genuinely broken business function stays broken for weeks because it was filed as an attack instead of as a rule that needs tuning.",
      xp: 30,
    },

    // ------------------------------------------------------------------
    // Ordering — the life of one request
    // ------------------------------------------------------------------
    {
      type: "ordering",
      id: "webapp-o1",
      heading: "Order the Life of a Single Web Request",
      instructions:
        "Arrange these steps in the order they actually happen for one request to a proxied web application, from the browser to the database and back.",
      items: [
        {
          id: "build",
          text: "The browser builds the request — method, path, query string, headers and cookies — and sends it over TLS to the site's public address",
        },
        {
          id: "waf",
          text: "The WAF terminates TLS, inspects the decrypted request against its signatures and anomaly score, and records the real client IP along with an ALLOW or BLOCK decision",
        },
        {
          id: "lb",
          text: "The load balancer opens its own separate connection to a backend web server, placing the original client address into an X-Forwarded-For header",
        },
        {
          id: "iis",
          text: "The web server receives the request and writes an access-log line — csUriStem and csUriQuery are captured, cIP records the load balancer, and the request body is not recorded at all",
        },
        {
          id: "app",
          text: "The application code runs, taking the parameter values as input and building a database query or a filesystem path from them",
        },
        {
          id: "db",
          text: "The database executes whatever query it was handed and returns the resulting rows to the application",
        },
        {
          id: "response",
          text: "The response travels back out, and the web server completes that same log line with scStatus and scBytes",
        },
      ],
      correct_order: ["build", "waf", "lb", "iis", "app", "db", "response"],
      explanation:
        "This ordering is the whole room in one sequence, and every lesson hangs off a specific step. The client builds the request, so by Reading 2 every part of it is attacker-controlled. The WAF is second, which is why it is the last component to see the real client IP and why its clientIp field is authoritative for attribution. The load balancer's new connection is the exact moment source visibility is lost, which is why the web server's cIP is its own infrastructure rather than the client. The access line is written with the query string but never the body, which is why POST-delivered attacks are nearly invisible there. The application is where the parameters become instructions, and the database is where an injected query finally executes — which is why the database's own audit log, not the web log, is what confirms what was actually read. And the status code and byte count are written last, which is exactly why they describe outcome rather than intent: they are the only fields in the line that know how the story ended.",
      xp: 35,
    },
  ],
};

export const roomsBatch25 = [webApplicationSecurityRoom];
