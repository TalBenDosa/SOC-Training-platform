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
 * IP, and whether any rule matched at all (action ALLOW, terminatingRuleId Default_Action).
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
    timestamp: 1779227045000,
    webaclId: "arn:aws:wafv2:eu-west-1:702844913065:regional/webacl/larkfield-shop-prod/9c41b7d2-05fe-4a63-8b17-2ad9e5c31f40",
    terminatingRuleId: "Default_Action",
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
    timestamp: 1779368932000,
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
    "Before you can investigate a web attack you have to know what a web request actually is. This room builds that from zero: what travels in an HTTP request and response, why nothing the browser sends can ever be trusted, the browser-to-server-to-application-to-database path every request takes, the attack classes that live at each stop mapped onto the OWASP Top 10 2021, what a WAF genuinely catches versus what it is blind to, and how to read a real IIS access-log line field by field — including two things it does not record by default: the request body, and, behind a load balancer, the true client IP.",
  difficulty: "beginner",
  category: "Application Security",
  estimatedMinutes: 60,
  xp: 335,
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
        `The web server's access log is one line per request: the method, the path, the query string, the address of the machine that opened the connection, a few headers such as User-Agent, the status code and the response size — but not the body. In the W3C format IIS uses, the field-name prefix gives the direction: cs- is client-to-server (csMethod, csUriStem, csUriQuery, csBytes), sc- is server-to-client (scStatus, scBytes), and cIP is the address of whichever machine connected to the web server.\n\n` +
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
      checkpoint: {
        question: "A product page turns the id value from the query string into a lookup for that product's row. Which tier runs that lookup with no way to tell whether a real shopper or an attacker sent the request behind it?",
        options: ["The web server (IIS)", "The application code", "The database server", "The visitor's browser"],
        answer: 2,
        explanation:
          "The database server runs whatever query it is handed and never sees the HTTP request that caused it, so it cannot judge who sent it. The web server (IIS) does see the request — it accepts the connection and logs it — but it only passes the request on and does not run the lookup. The application code is the tier that builds the query from the id value, so it is where the trust decision is made, but building a query is not running it. The visitor's browser only sends the id value; it is where untrusted input starts, not where the lookup runs.",
      },
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
      checkpoint: {
        question: "A checkout page uses JavaScript to stop shoppers entering a quantity above 10. Your log shows an order request carrying quantity=500, which the server accepted. What is the best explanation?",
        options: [
          "The JavaScript check had a bug, since a value the form blocks could not otherwise reach the server",
          "The request was sent without running the page's check, which runs on the client and can be skipped",
          "The log line is probably corrupted, since the form itself cannot produce a quantity above 10",
          "The request came from an administrator account, whose sessions are exempt from the page's checks",
        ],
        answer: 1,
        explanation:
          "JavaScript validation runs on the client's own machine, so anyone can skip it and send the request directly with a proxy, a command-line tool or a short script. A value the form forbids is therefore exactly what you should expect from a request that did not come from the form. Blaming a bug in the check assumes the form is the only way to reach the server, which Reading 2 says it is not. Calling the log corrupt is the mistake Reading 2 warns against: assume the value was sent on purpose. An administrator account does not explain it either: the page applies the same check to every visitor, and the value got through because the check never ran, not because of who was logged in.",
      },
    },

    // ------------------------------------------------------------------
    // Question 1 — the POST body blind spot
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "webapp-q1",
      question:
        "A login form submits its fields in the body of a POST request to /login.aspx, and one submission carries SQL keywords in the username field. You open the IIS access log for that exact second. What do you see?",
      options: [
        "The SQL text, in the line's csUriQuery field, because the access log records every parameter whichever method carried it",
        "A POST to /login.aspx with csUriQuery empty (“-”) and no SQL text anywhere, because the log keeps the request line and a few headers",
        "No line at all, because IIS writes access-log lines for GET requests only unless an extra tracing feature is switched on",
        "The SQL text, appended to /login.aspx in the csUriStem field, because a POST sends its form fields as part of the URL",
      ],
      answer: 1,
      explanation:
        "As Reading 1 lists, a W3C access-log line holds the method, path, query string, client address, a few headers, the status and the sizes — not the body — so a POST that carries SQL text in its form fields leaves a line that looks completely ordinary. csUriQuery holds only the query string after the question mark, which a POST form usually leaves empty, so the SQL text cannot show up there. IIS does log POST requests; they simply look unremarkable. And a POST does not put its form fields into the URL — that is how a GET form behaves — so csUriStem shows just /login.aspx. This is why POST-delivered attacks are nearly invisible in web-server logs alone, and why you need WAF, application or database audit logs to see them.",
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
        `Now put Reading 1's three-tier path together with Reading 2's rule that everything from the client is hostile, and the attack classes almost derive themselves. Each one is untrusted input reaching a tier that treats it as instruction rather than as data. What changes between them is WHICH tier gets fooled, and therefore which log holds the evidence. The category names below are the OWASP (Open Worldwide Application Security Project) Top 10 2021, the industry's standard list of the ten most critical web application security risks — knowing which bucket an attack falls into is how you talk to a developer about it.\n\n` +
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
        "Larkfield's online shop has a datasheet download page at /download.aspx, which takes a file parameter and returns the requested product PDF. Visitors do not reach the web server WEB-LKF01 (10.44.2.30) directly: an AWS Application Load Balancer (ALB) accepts every visitor's connection and forwards each request on to it. Normal responses from this endpoint run between 240,000 and 900,000 bytes. Over four minutes on 19 May, this endpoint received 31 requests from the same session, each carrying a different value in the file parameter. The record below is one of them. Work through the fields one at a time.",
      event: larkfieldDownloadEvent,
      questions: [
        {
          question:
            "Start with the request itself. csMethod is GET, csUriStem is /download.aspx and csUriQuery is 'file=..%2f..%2f..%2fWindows%2fwin.ini'. What is the client asking for, once you decode it?",
          options: [
            "A datasheet named win.ini, read from the usual download folder that the file parameter normally points to",
            "A file outside the download folder: %2f decodes to “/”, so the value climbs three folders up to Windows/win.ini",
            "Nothing usable: %2f is an encoding error, so the server would treat the value as plain text and show an error page",
            "Several files at once: each ..%2f separates one requested name, and win.ini is simply the last name in the list",
          ],
          answer: 1,
          explanation:
            "%2f is the standard URL encoding of a forward slash, so the decoded value reads ../../../Windows/win.ini: three “go up one folder” steps out of the folder the application intended, then a path to a system file elsewhere on the server. That is the path traversal shape from Reading 3, and encoding the slashes is a common way to slip past filters that look only for literal dot-dot-slash text. It is not a datasheet in the download folder, because the ../ steps move the lookup out of that folder before win.ini is named. %2f is not an encoding error — it is valid and very common — and the 200 status shows the server did not answer with an error. And ..%2f is not a list separator: decoded it is ../, one step up the folder tree, so the value names one file, not several.",
          xp: 25,
        },
        {
          question:
            "Now read the outcome fields. scStatus is 200 and scBytes is 5,312, against this endpoint's normal range of 240,000 to 900,000 bytes. Why is this pairing more serious than the same request returning 403?",
          options: [
            "It is not more serious: a 200 only shows the web server received the request, and the application may still have refused it",
            "A 403 means it was refused; a 200 means the application answered, and 5,312 bytes is far too small to be a datasheet PDF",
            "A 200 means a security check inspected the request and approved it, so the traversal text was judged harmless before it ran",
            "scBytes is the size of what the client sent, so 5,312 reflects the long query string and says nothing about what came back",
          ],
          answer: 1,
          explanation:
            "Status code is OUTCOME, not intent — the most important reading skill in this room. A 403 means something refused the request and the application never acted on it: an attempt, and a blocked one. A 200 means the request went all the way through and a body came back, so the question becomes what was returned, and the byte count answers it: 5,312 bytes is nowhere near a 240,000-byte-plus PDF, but fits a small system text file. A 200 is not a mere receipt — a refusal by the application would show as an error code such as 403 or 500, not 200. Nor is a 200 a security approval: it is the web server's report of what it sent back, and nothing in a status code says any check judged the content safe. And by Reading 1's prefix rule, sc- means server-to-client, so scBytes is the size of the response; the client's side is csBytes (488 here).",
          xp: 25,
        },
        {
          question:
            "One more field before you escalate. cIP shows 10.44.2.7 — a private, internal address, even though shop.larkfield.com is a public internet-facing site. What should you conclude?",
          options: [
            "The request came from a machine inside Larkfield's network, so the investigation should start on the host at 10.44.2.7",
            "cIP is the load balancer, which made its own connection to IIS; the real client has to come from an upstream log",
            "cIP is the web server's own address, which IIS records as the network interface that the request arrived on",
            "cIP was forged: by Reading 2 the client controls the whole request, so this value is unreliable and should be ignored",
          ],
          answer: 1,
          explanation:
            "Per Reading 1, cIP is the address of whichever machine connected to the web server, and the task context says every visitor reaches WEB-LKF01 through the ALB. So IIS has correctly logged the ALB's own internal address (a private, RFC 1918 range address), and the real client must come from a log written further upstream. Starting on 10.44.2.7 as an insider would send you to investigate your own load balancer — the wrong-host mistake this room exists to prevent. cIP is not the web server's address: that is sIP, which reads 10.44.2.30 on this same line. And cIP is not a value the client writes: it comes from the network connection itself, not from a header or parameter, so Reading 2's rule about attacker-controlled request content does not apply to it — it is accurate, it simply names the wrong machine for attribution.",
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
        `Two mechanisms, working together. SIGNATURE MATCHING compares the request against a catalogue of known-bad patterns — SQL keywords in odd places, script tags in parameters, dot-dot-slash sequences, shell metacharacters. Cloud WAFs ship these as managed rule groups, and when a request trips one, the log records which rule ended the evaluation (in AWS WAF, terminatingRuleId) and what was done about it (action: BLOCK or ALLOW). ANOMALY SCORING adds up smaller oddities — an unusually long parameter, an unusual character mix, too many parameters — and blocks once the total crosses a threshold, catching things no single signature would. The critical field to read in any WAF log is therefore the action, and the second most critical is whether any rule matched at all: an ALLOW with terminatingRuleId Default_Action means no rule even fired and the web ACL's default action applied, which is a very different statement from a rule firing and deciding the request was acceptable.\n\n` +
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
        "                     Default_Action -> no rule fired;\n" +
        "                     the ACL default applied\n" +
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
        "A customer logs into Larkfield's portal legitimately, then edits the URL /invoice.aspx?id=88412 to id=88413 and receives another customer's invoice with a 200 response. The WAF logged the request with action ALLOW and terminatingRuleId Default_Action. Why did the WAF not stop it?",
      options: [
        "The managed rule groups were not enabled on this web ACL, and switching on the full standard rule set would have blocked a request like this",
        "The request is well-formed with nothing to match; whether it is theft depends on who owns invoice 88413, which the WAF cannot know",
        "The WAF skips inspection of requests carrying a valid authenticated session cookie, treating logged-in traffic as trusted by default",
        "The WAF inspects POST bodies but not query strings, so a GET request carrying id=88413 in its URL passes through uninspected",
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
            "10.44.2.7, because the web server sits nearer the application and so records the more accurate source address",
            "45.147.230.19: the WAF saw the client's own connection, while IIS logged the load balancer's onward connection",
            "Neither: one request with two different source addresses means one of the logs was altered, so both are suspect",
            "45.147.230.19, because the WAF record is one second earlier, and the earlier of two logs is the original record",
          ],
          answer: 1,
          explanation:
            "The two records describe two different connections that together carry one request: the client-to-WAF connection, where the real source is visible, and the load-balancer-to-IIS connection, where the source is the load balancer itself. Being nearer the application is exactly what loses source visibility here, so 10.44.2.7 is the less useful address, not the more accurate one — following it means investigating Larkfield's own load balancer. Two addresses for one request are expected on a proxied site, not a sign of tampering; both logs are correct about the connection each one saw. And the one-second gap is not the reason: timestamps only helped match the two records, while trust comes from which component saw the real connection — had the earlier record been IIS's, it would still show the load balancer.",
          xp: 25,
        },
        {
          question:
            "action is ALLOW and terminatingRuleId is Default_Action. What does that combination actually mean, and what does it tell you about how much protection the WAF provided here?",
          options: [
            "A rule inspected the request, judged it safe and explicitly allowed it, so the WAF has vouched for this traffic",
            "No rule matched: the encoded traversal hit no signature, so the default action let it through to the application",
            "The request was logged for visibility but held back at the WAF, so it never reached the application behind it",
            "A managed rule blocked it, but the web ACL's default action then overrode that block and let the request through",
          ],
          answer: 1,
          explanation:
            "This is the distinction Reading 4 flagged: terminatingRuleId Default_Action means evaluation ran to the end without any rule matching, and the web ACL's default action — here ALLOW — was applied. That is a statement about the rule set's coverage, not a clean bill of health; combined with the IIS record's 200 and tiny byte count, it says a traversal attempt reached the application and got an answer. No rule vouched for the request: had a rule decided it, its own name would appear in terminatingRuleId instead of Default_Action. ALLOW means forwarded, not held back — and the matching IIS line proves the request arrived. And a rule that blocks ends evaluation there (that is what “terminating” means), so the default action never gets a chance to override it; a blocked request would show action BLOCK and that rule's ID.",
          xp: 25,
        },
        {
          question:
            "You now have a confirmed source and confirmed evidence the application answered. What is the right next step?",
          options: [
            "Add a deny rule for 45.147.230.19 in IIS, since IIS is the server that received and processed the request",
            "Block 45.147.230.19 at the WAF, which sees that address; scope its other requests; get the file parameter fixed",
            "Block 10.44.2.7 at the perimeter firewall, since that is the source address the web server logged for the request",
            "Get the file parameter fixed but leave the address unblocked, since a source-IP block is easy to evade anyway",
          ],
          answer: 1,
          explanation:
            "Block where the real address is visible: the WAF is the first component that sees 45.147.230.19, and its clientIp field is also your pivot for finding every other request this source made. Fixing the file parameter is still needed, because an IP block alone is easy to evade by moving address. A deny rule in IIS would have nothing to match, because IIS never sees 45.147.230.19 — every request reaches it from the load balancer's address. Blocking 10.44.2.7 would cut off Larkfield's own load balancer and take the site offline for every visitor. And fixing the parameter while leaving the source unblocked is the right fix with the wrong timing: the code change takes time, and until it ships an active source that the application is already answering keeps its access, while you still have not scoped what else it touched.",
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
        "Decode the argument string and the picture resolves: surname=O%27Brien is simply the surname O'Brien, where %27 is the URL encoding of an apostrophe. An apostrophe is the exact character SQL injection uses to break out of a string literal, so a signature scanning for it in a parameter fires on a genuine Irish surname just as readily as on a payload — and there is no second SQL keyword, no UNION, no comment marker, no OR 1=1 anywhere in the request. Everything else corroborates the mundane reading: the Referer header shows the request came from the lookup page itself, the branch parameter carries an ordinary value (BRS), and the helpdesk note attached under the record identifies 198.51.100.62 as the Bristol branch office egress address and quotes ticket HD-44127, raised the same afternoon, describing staff hitting an error page on exactly this kind of search. The correct outcome is not an escalation but a rule tuning request, because until it is fixed, staff cannot serve any customer whose surname contains an apostrophe.",
      fp_trap:
        "Everything about the surface of this record argues for escalation: a BLOCK action, the SQL injection managed rule group as the terminating rule, and an encoded quote character sitting in a parameter — which is genuinely the first thing real SQL injection looks like. The habit that saves you is decoding the argument string and asking what the value would mean if it were innocent, before asking what it would mean if it were hostile. Real injection needs more than a quote: it needs SQL that does something once the quote has broken out of the string, and none is present here. Escalating every SQLi-signature block without decoding the parameter and checking the source and the Referer is how analysts spend a day on a customer surname — and, worse, how a genuinely broken business function stays broken for weeks because it was filed as an attack instead of as a rule that needs tuning.",
      xp: 30,
    },

    // ------------------------------------------------------------------
    // Reading 5 — CSRF
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "webapp-r5",
      heading: "CSRF: When the Browser's Own Trust Becomes the Weapon",
      content:
        `Cross-Site Request Forgery, CSRF, is the one attack class in this room that needs no vulnerability in the target site's code at all -- no injection point, no unescaped output, nothing planted anywhere on Larkfield's own pages. It exploits a single fact from Reading 2: the browser attaches cookies to every request it sends to a domain automatically, regardless of which page on screen triggered that request. If a victim is logged into Larkfield's portal in one tab, with a valid session cookie sitting in the browser, and opens a completely unrelated page in another tab, that unrelated page can make the victim's browser send a request to Larkfield -- and the browser will dutifully attach the real session cookie to it, because as far as the browser is concerned, a request to portal.larkfield.com is a request to portal.larkfield.com, no matter which tab asked for it. Think of it as a courier who checks your ID card at your own front door before handing over a package, but never checks who actually rang the doorbell to summon them there in the first place.\n\n` +
        `**The Attack, Worked Through**\n\n` +
        `A Larkfield customer is logged into the support portal; their browser is holding a valid, genuine session cookie. They then visit an unrelated site -- perhaps a link from a phishing email, perhaps just an ordinary page carrying a malicious ad -- and that page contains a form the victim never sees, styled to be invisible, with its action pointed at Larkfield's own money-handling endpoint: something equivalent to POST https://portal.larkfield.com/account/transfer with fields amount=5000 and to=attacker. A small script on the malicious page submits that form the instant the page loads, with no click required from the victim at all. The victim's browser builds the request exactly as it would for any legitimate request to that domain, attaches the real session cookie automatically, and sends it. From Larkfield's server's point of view, this is indistinguishable from the customer clicking a genuine transfer button on Larkfield's own site: the session is valid, the user is authenticated, the request is well-formed. Nothing in the request itself says it was not the customer's own idea.\n\n` +
        `**CSRF vs XSS: The Distinction That Actually Matters**\n\n` +
        `It is easy to blur CSRF into XSS from Reading 3, and the two get confused constantly, but the mechanism is genuinely opposite. Stored or reflected XSS needs the attacker's script to actually execute inside the vulnerable site's own origin -- it is a code-injection problem, and the payload has to reach the target application's pages before it can do anything. CSRF needs none of that: no script ever runs on portal.larkfield.com, no output is ever injected into a Larkfield page, and the malicious form lives entirely on the attacker's own unrelated site the whole time. What CSRF exploits is not a flaw in what Larkfield renders, but a structural property of how browsers handle cookies -- trust that was never conditional on which page asked for the request in the first place. It is also worth separating from IDOR, from the same room: in IDOR the logged-in user IS the attacker, deliberately walking through record identifiers in their own session, and the victims are the people who own those records. CSRF is the attacker's page, silently forcing the victim's browser to make a request the victim never intended to send at all. Same broad family -- OWASP retired CSRF as a standalone Top 10 category in 2017 because modern frameworks now default to CSRF protection, but the vulnerability itself still belongs conceptually inside A01:2021 Broken Access Control, the exact category IDOR sits in from Reading 3, because both are failures to confirm that this specific action was actually authorized for this specific request, rather than just trusting that the session is valid.\n\n` +
        `**The Real Defenses**\n\n` +
        `A CSRF token is the standard fix: the server embeds a random, unpredictable value in a hidden field or a custom header on every form it renders, and checks that the same value comes back with the submission. An attacker's page, sitting on a different origin, has no way to read that token off Larkfield's page to include it -- the browser's same-origin policy blocks JavaScript on one site from reading the content of a page loaded from another -- so a forged form can send the victim's cookie automatically, but it cannot produce a valid token to go with it. The second defense sits in the cookie itself: the SameSite attribute tells the browser under what conditions to attach a cookie to a cross-site request at all. SameSite=Strict never attaches the cookie to any request that did not originate on the same site, which blocks CSRF outright but can break legitimate cross-site links into the app. SameSite=Lax, which Chrome and Edge apply by default to cookies that don't set the attribute (Firefox and Safari do not, relying on other tracking protections), still attaches the cookie to plain top-level navigation -- clicking a genuine link -- but withholds it from the kind of background, auto-submitted POST a CSRF attack relies on, which is why classic CSRF against modern, unmodified browsers is far rarer than it was a decade ago. The third layer is server-side: checking that the Origin or Referer header on a state-changing request actually matches Larkfield's own domain, rejecting anything that does not.\n\n` +
        `**Reading This in Logs**\n\n` +
        `This is the part that makes CSRF genuinely hard to hunt for, and it connects straight back to Reading 4's account of what a WAF cannot see. There is no injection signature to match, because there is no injected content -- the request body is ordinary form data, the cookie is completely genuine, and the method, path and parameters are all exactly what a legitimate request to that endpoint would look like. A signature-matching rule group has nothing to fire on. The one field that can still betray it is Origin or Referer: a state-changing POST or PUT to a sensitive endpoint -- a transfer, an email change, a password reset -- arriving with a Referer header pointing at a domain that has no legitimate reason to be sending traffic to Larkfield at all is the tell, not a payload inside the request. A missing or invalid CSRF token on a request that should be carrying one is the second tell, when the application logs that check. Neither of those, on its own, proves anything -- some browsers and privacy tools strip Referer entirely on legitimate requests -- which is exactly why this sits in the same bucket as IDOR from Reading 3: a well-formed, technically valid request where the verdict depends on context the log only partly hands you, not on a pattern a WAF rule can match.`,
      codeExample:
        "CSRF: THE ONLY REAL TELL, SEEN ON THE WIRE\n" +
        "=======================================================\n" +
        "POST /account/transfer HTTP/1.1\n" +
        "Host: portal.larkfield.com\n" +
        "Referer: https://free-prize-wheel.example/spin.html\n" +
        "Cookie: session=8f2a1c9e...   (the VICTIM's own genuine cookie)\n" +
        "Content-Type: application/x-www-form-urlencoded\n\n" +
        "amount=5000&to=attacker\n" +
        "=======================================================\n" +
        "Nothing here is malformed. No quote, no script tag, no\n" +
        "traversal sequence. The cookie is entirely real. The one\n" +
        "anomaly is the Referer: a state-changing POST to a\n" +
        "money-transfer endpoint, arriving from a domain that has\n" +
        "no legitimate reason to be sending traffic to Larkfield\n" +
        "at all.\n" +
        "=======================================================\n\n" +
        "CSRF vs XSS vs IDOR -- WHERE EACH ONE ACTUALLY RUNS\n" +
        "=======================================================\n" +
        "XSS    Attacker's script executes ON the target site\n" +
        "       itself, inside its own origin.\n" +
        "CSRF   Attacker's page lives on a DIFFERENT origin and\n" +
        "       never executes anything on the target site --\n" +
        "       it just rides the victim's browser's own\n" +
        "       automatic cookie attachment.\n" +
        "IDOR   The ATTACKER's own logged-in session, used\n" +
        "       deliberately to walk through record identifiers\n" +
        "       that belong to other people.\n" +
        "=======================================================",
    },

    // ------------------------------------------------------------------
    // Question 3 — CSRF vs XSS vs IDOR
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "webapp-q3",
      question:
        "A Larkfield customer, still logged into the support portal in one browser tab, opens a link in another tab to an unrelated raffle site. Moments later your WAF log shows a POST to /account/change-email arriving at the portal with a Referer header of https://win-a-prize.example/enter.html, and the portal's application log records that the request carried the customer's genuine, valid session but not the anti-CSRF token the change-email form normally includes. What does this pattern indicate, and how does it differ from an IDOR or a stored-XSS attack?",
      options: [
        "Stored XSS: a script injected into the portal ran in the victim's browser, read the session cookie and forged the change-email request from inside Larkfield's own origin",
        "CSRF: the raffle page auto-submitted a hidden form, and the browser attached the victim's cookie by itself, so no script ever ran on Larkfield's site",
        "IDOR: the customer altered an identifier in the request to reach another account's email settings, and the WAF missed it because the request is well-formed",
        "Not CSRF: that technique needs the attacker to have stolen the session cookie in advance and replayed it, and nothing in this record shows a stolen cookie",
      ],
      answer: 1,
      explanation:
        "This is the CSRF shape from Reading 5: a genuinely valid session, a well-formed state-changing request, a Referer pointing at a domain with no legitimate business talking to Larkfield, and a missing anti-CSRF token — the forged form on the raffle page could send the cookie but could not read the token from Larkfield's page. It is not stored XSS: a script running inside the portal would send the request from Larkfield's own pages, so the Referer would be a Larkfield page, and nothing here shows injected content running on portal.larkfield.com — the request arrived FROM an unrelated external site. It is not IDOR: in IDOR the logged-in user is the attacker, deliberately changing an identifier to reach someone else's record, whereas here the customer did not intend the request at all, and it acts on the customer's own account rather than on someone else's record. And “not CSRF because no stolen cookie is shown” gets the mechanism backwards: CSRF never needs to steal the cookie, because the victim's own browser attaches it automatically — which is why the missing token and the stray Referer are the tell, not the cookie.",
      xp: 25,
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
          text: "The browser builds the request — method, path, query string, headers and cookies — and sends it over TLS (the encryption behind HTTPS) to the site's public address",
        },
        {
          id: "waf",
          text: "The load balancer decrypts the TLS connection, and the WAF attached to it inspects the request, recording the real client IP and an ALLOW or BLOCK decision",
        },
        {
          id: "lb",
          text: "If the WAF allowed it, the load balancer opens its own separate connection to a backend web server, placing the original client address into an X-Forwarded-For header",
        },
        {
          id: "iis",
          text: "The web server accepts that connection from the load balancer and hands the request to the application code behind it",
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
          text: "The web server sends the response back out and only then writes the request's single access-log line — scStatus, scBytes, query string, cIP of the load balancer, and no body",
        },
      ],
      correct_order: ["build", "waf", "lb", "iis", "app", "db", "response"],
      explanation:
        "This ordering is the whole room in one sequence, and every lesson hangs off a specific step. The client builds the request, so by Reading 2 every part of it is attacker-controlled. The load balancer decrypts the traffic and its attached WAF inspects the request before anything is forwarded, which is why the WAF still sees the real client IP and why its clientIp field is authoritative for attribution. The load balancer's new connection to the backend is the exact moment source visibility is lost, which is why the web server's cIP is Larkfield's own infrastructure rather than the client. The application is where the parameters become instructions, and the database is where an injected query finally executes — which is why the database's own audit log, not the web log, confirms what was actually read. And IIS writes its access-log line once, after the response has been sent: that is why the line can contain the status code and byte count, why those fields describe outcome rather than intent, and why — holding the query string but never the body — it leaves POST-delivered attacks nearly invisible.",
      xp: 35,
    },
  ],
};

export const roomsBatch25 = [webApplicationSecurityRoom];
