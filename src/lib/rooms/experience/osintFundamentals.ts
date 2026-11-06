import type { RoomExperience } from "./types";

// "Operation Open Source" for the "osint-fundamentals" room.
// Script: docs/campaign/100-osint-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// New task order (the room lists every reading first, so it does not group):
//   osint-r1 | osint-r2, osint-q2 | osint-r3, osint-q1, osint-q3 | osint-la1, osint-flag1, osint-q4
// la1 stays directly before flag1, whose prompt says "the log above". The readings keep their order.
//
// Larkhill Veterinary Group (fictional), not the graded tasks' LAPTOP-JSMITH records.
// Signature: See Yourself as the Attacker Does. The learner maps the company's own exposure:
// evidence screens of a certificate log, a job advert, a breach notice and photo metadata, then a
// codebreak on search operators, all aimed at larkhillvets.example and never at a target's server.
// Game mix: codebreak + deduce + spotdiff. Room 59 teaches IOC pivoting, so nothing here pivots:
// the only mention is the name of the technique, which q2 needs.
// Lab data differs from the graded tasks: categories are sorted on a certificate log, an advert, a
// notice and a photo, never on an IP's owner, ports and certificate (r1 checkpoint); the WHOIS
// record is Larkhill's own 2011 domain, shown as data and never asked for by tool (r2 checkpoint);
// the operator rounds search Larkhill's own domain, never a phishing certificate (q2); the plan's
// active steps are a zone transfer, a test email and a login, never a port scan or a block (q1);
// the sandbox case is a canary on Larkhill's own domain, and the visibility table is staff pasting
// their own links and a PDF, never a phishing link with a recipient's number (q3) or a suspicious
// attachment (q4); the scanner record is a forgotten Larkhill Windows server tagged eol-product
// on one port, never a Linux host with a relay tag (la1), and its certificate name is Larkhill's (flag1).
// Same Ports, Different Host teaches la1's decisive field on cloud, vpn, honeypot, self-signed and
// cdn records, on ports that differ from la1.

export const OSINT_FUNDAMENTALS: RoomExperience = {
  roomId: "osint-fundamentals",
  codename: "Operation Open Source",
  theme: "opensource",
  handler: { name: "Maren Abiodun", role: "OSINT Analyst, Larkhill Veterinary Group" },
  briefing: [
    "Larkhill Veterinary Group. Fourteen clinics, one out-of-hours hospital, and a reception desk at Ashcombe that got a very well-informed email on Tuesday.",
    "It named the group's imaging server, its firewall and its practice manager. Nobody inside Larkhill gave those away.",
    "Maren Abiodun thinks all of it was public. Before the next email lands, Maren wants to see what the sender saw.",
    "Map Larkhill the way a stranger would, stay on the right side of the line, touch nothing, and then make the call when a laptop starts talking to a server nobody knows.",
  ],
  mission: "Find what a stranger can see of Larkhill, match each question to the tool that answers it, crack the search operators, hold the line between reading and touching, then work a live alert from public data alone.",
  estimate: "~45 min",
  look: { primary: "#9fd356", secondary: "#ffb347", warn: "#ff6b5e" },
  scene: "facilityopensource",
  layout: "facility",
  stations: [
    {
      id: "footprint",
      label: "The Footprint",
      topic: "What OSINT is · the jobs it does in a SOC · the five OSINT categories",
      tagline: "What can a stranger see?",
      building: "archive",
      taskIds: ["osint-r1"],
    },
    {
      id: "toolkit",
      label: "The Toolkit",
      topic: "Shodan, Censys, URLScan.io, WHOIS, DNSDumpster, Maltego · search operators",
      tagline: "Ask where the answer is already stored",
      building: "lab",
      taskIds: ["osint-r2", "osint-q2"],
    },
    {
      id: "line",
      label: "The Line",
      topic: "Passive and active OSINT · active by proxy · analyst OPSEC · scan visibility · hashes and uploads",
      tagline: "Reading is fine. Touching is not.",
      building: "control",
      taskIds: ["osint-r3", "osint-q1", "osint-q3"],
    },
    {
      id: "readonly",
      label: "Read Only",
      topic: "Reading a scanner record · the next step from public data alone",
      tagline: "One alert, and no packets of yours",
      building: "ticket",
      taskIds: ["osint-la1", "osint-flag1", "osint-q4"],
      boss: true,
    },
  ],
  personas: {
    "osint-q2": { name: "Maren Abiodun", role: "OSINT Analyst", line: "You just ran that search. What's it called when you write it up?" },
    "osint-q1": { name: "Maren Abiodun", role: "OSINT Analyst", line: "An address nobody here knows. Walk me through your first move." },
    "osint-q3": { name: "Maren Abiodun", role: "OSINT Analyst", line: "You want to see that page. Tell me how you'll run it." },
    "osint-la1": { name: "Maren Abiodun", role: "OSINT Analyst", line: "The enrichment came back. Read it to me." },
    "osint-flag1": { name: "Maren Abiodun", role: "OSINT Analyst", line: "Give me the exact string you'd search for." },
    "osint-q4": { name: "Maren Abiodun", role: "OSINT Analyst", line: "Four options on the desk. Which one holds up?" },
  },
  briefings: {
    // ── Reading 1: what OSINT is and how it sorts ──
    "osint-r1": [
      {
        kind: "evidence",
        title: "See Yourself as the Attacker Does",
        prompt: "Tuesday's email knew Larkhill's imaging server, its firewall and its people, and nobody inside sent those. Maren has pulled four public screens about the group. Name the OSINT category of each one, then read what it gives away.",
        primer: {
          title: "What OSINT Is, and How It Sorts",
          points: [
            "**OSINT** is Open Source Intelligence: information anyone can get without hacking, bribing or breaking a law. 'Open source' here means public, not software.",
            "It does three jobs in a SOC: enriching an indicator from an alert, researching an attacker's infrastructure, and showing what an attacker can see about you. Larkhill needs the third job today.",
            "Analysts sort it by subject: **Infrastructure** (machines and the names on them), **Organisation** (a company and how it runs), **People** (one person and their accounts), **Geolocation** (a place on the map), **Social media** (public posts and connections).",
            "Sort a fact by what it is about.",
          ],
          example: {
            label: "Sorting one fact by its subject",
            lines: [
              "Fact: a bakery's owner uses the handle crumbqueen on three forums.",
              "What is this about? One person and their accounts.",
              "Category: People.",
            ],
          },
        },
        choices: [
          { id: "infra", label: "Infrastructure OSINT" },
          { id: "org", label: "Organisation OSINT" },
          { id: "people", label: "People OSINT" },
          { id: "geo", label: "Geolocation OSINT" },
          { id: "social", label: "Social media OSINT" },
        ],
        items: [
          {
            id: "ct",
            caption: "Public log search",
            screen: {
              type: "leak",
              site: "ct-search.example · certificate transparency logs",
              title: "Identity search: %.larkhillvets.example",
              meta: "6 of 41 entries, newest first. Expired entries stay listed.",
              header: ["entry_timestamp", "not_after", "common_name", "issuer_name"],
              rows: [
                ["2026-10-02T06:14:51", "2026-12-31", "www.larkhillvets.example", "Example Trust DV R3"],
                ["2026-09-28T06:02:17", "2026-12-27", "portal.larkhillvets.example", "Example Trust DV R3"],
                ["2026-09-14T11:40:09", "2026-12-13", "vpn.larkhillvets.example", "Example Trust DV R3"],
                ["2026-08-30T09:12:33", "2026-11-28", "pacs-staging.larkhillvets.example", "Example Trust DV R3"],
                ["2026-08-11T06:21:48", "2026-11-09", "mail.larkhillvets.example", "Example Trust DV R3"],
                ["2024-03-03T10:05:26", "2024-06-01", "oldbooking.larkhillvets.example", "Example Trust DV R3"],
              ],
            },
            answer: "infra",
            callouts: [
              { at: "site", text: "Certificate Transparency (CT) logs are public, append-only records of the certificates public authorities issue. Major browsers reject a public certificate that was never logged, so a company cannot opt out. Certificates from a private internal authority are not logged." },
              { at: "title", text: "This search lands on the log's website, not on Larkhill, so Larkhill sees nothing. The % is a wildcard: it returns every name under the domain." },
              { at: "rows", text: "pacs-staging is an imaging server (PACS, Picture Archiving and Communication System) that no page links to, and the email named it. oldbooking's certificate ended in 2024 and it is still listed. Hostnames and certificates describe machines, so this is Infrastructure OSINT." },
            ],
          },
          {
            id: "advert",
            caption: "Careers page, no login",
            screen: {
              type: "leak",
              site: "careers.larkhillvets.example",
              title: "Senior Systems Administrator, Central Services",
              meta: "Posted 12 days ago. Public and indexed by search engines.",
              header: ["section", "text"],
              rows: [
                ["Essential", "Day-to-day admin of FortiGate firewalls on FortiOS 7.2"],
                ["Essential", "Microsoft 365 with on-premises Exchange 2019"],
                ["Essential", "Veeam backup to an on-site repository"],
                ["Desirable", "Experience of the Q2 move off Windows Server 2016"],
                ["Reports to", "T. Renwick (Head of IT)"],
              ],
            },
            answer: "org",
            callouts: [
              { at: "title", text: "A job advert has to be specific to find the right person, and an attacker reads the same page as the candidates." },
              { at: "rows", text: "Vendor, product and version: a stranger now knows which advisories to read about Larkhill and which login page to fake, and has sent nothing to Larkhill. The advert names a firewall, but its subject is the company and how it runs, so this is Organisation OSINT." },
              { at: "site", text: "The fix is one edit. 'Enterprise firewalls' finds the same candidates as a product and a version number." },
            ],
          },
          {
            id: "breach",
            caption: "Public address lookup",
            screen: {
              type: "leak",
              site: "breach-lookup.example · public address search",
              title: "3 Larkhill addresses found in known breaches",
              meta: "Anyone can search an address. Passwords are never displayed.",
              header: ["address", "breach", "breach_date", "data_classes"],
              rows: [
                ["m.okoro@larkhillvets.example", "pawprint-forum.example", "2024-06", "email; username; password hash"],
                ["j.tindall@larkhillvets.example", "vetjobs-board.example", "2025-02", "email; name; phone"],
                ["reception.ashcombe@larkhillvets.example", "pawprint-forum.example", "2024-06", "email; username; password hash"],
              ],
            },
            answer: "people",
            callouts: [
              { at: "site", text: "The breach happened at someone else's site, not at Larkhill. It matters if a person used the same password at work, and it hands an attacker a real address to write to." },
              { at: "rows", text: "Each row is about one person or their account: the address, where they signed up, what was exposed. So this is People OSINT. reception.ashcombe is the mailbox that got Tuesday's email." },
              { at: "title", text: "The line starts here. Reading a lookup result is passive. Testing an exposed password on a Larkhill login is an access attempt, not research. The right move is a forced reset." },
            ],
          },
          {
            id: "photo",
            caption: "Metadata viewer, archived copy",
            screen: {
              type: "leak",
              site: "web archive snapshot · larkhillvets.example/news",
              title: "ashcombe-refit.jpg, from the post 'Our New Prep Room'",
              meta: "Read from an archived copy. Larkhill's own site got no request.",
              header: ["tag", "value"],
              rows: [
                ["DateTimeOriginal", "2026:09:17 08:42:11"],
                ["ImageDescription", "Prep room and comms cabinet"],
                ["GPSLatitude", "51.2050 N"],
                ["GPSLongitude", "2.6190 W"],
              ],
            },
            answer: "geo",
            callouts: [
              { at: "rows", text: "A phone can store its GPS position in a photo's EXIF metadata, and here it survived the upload. It puts the comms cabinet in one known back room. A place on the map is Geolocation OSINT." },
              { at: "title", text: "Large social platforms usually strip EXIF on upload. Small company websites often keep it, so strip it before you publish." },
              { at: "site", text: "The archive fetched this page earlier. Reading its copy sends nothing to Larkhill's web server." },
            ],
          },
        ],
      },
    ],
    // ── Reading 2: the toolkit ──
    "osint-r2": [
      {
        kind: "match",
        title: "Which Tool Answers It?",
        prompt: "A stranger has six questions about Larkhill. Maren wants you asking them first. Match each question to the tool that already holds the answer.",
        primer: {
          title: "Six Tools and What They Hold",
          points: [
            "**Shodan** scans the public internet all the time and indexes what it finds: open ports, running services, software versions, certificates, device types.",
            "**Censys** is a similar index, and it is strongest on TLS certificates: it can find all the addresses using one certificate.",
            "**URLScan.io** opens a URL in a sandboxed browser and records a screenshot, the network requests, the page content and any downloads.",
            "**DNSDumpster** shows a domain's DNS records: A (addresses), MX (mail servers), TXT and subdomains.",
            "**Maltego** draws IPs, domains, emails and people as a graph, and its transforms query other sources to grow it. **OSINT Framework** is a directory of tools by category.",
          ],
          example: {
            label: "Picking a tool from the question",
            lines: [
              "Question: has this parcel left the depot?",
              "That answer is stored at the courier, so you look there, not on the shop's website.",
              "Same habit here: ask where the answer is already stored.",
            ],
          },
        },
        pairs: [
          { id: "ports", left: "Which ports are open on Larkhill's public address, and what software answers on them?", right: "Shodan", why: "Shodan has already been there and written it down, so a lookup reads its index. Key fields include org, asn, port and hostnames." },
          { id: "certs", left: "Which addresses on the internet use the certificate from portal.larkhillvets.example?", right: "Censys", why: "Censys indexes certificates, so one certificate leads to all the addresses using it." },
          { id: "link", left: "What does this link really do when a browser opens it?", right: "URLScan.io", why: "It opens the link in its own sandboxed browser, so you read the screenshot and the request list instead of opening it yourself." },
          { id: "dns", left: "Which subdomains and mail servers does larkhillvets.example have?", right: "DNSDumpster", why: "It shows the DNS records and subdomains of a domain, from data it already holds." },
          { id: "graph", left: "How do this address, these three domains and that email address connect?", right: "Maltego", why: "Start from one entity, run transforms, and the graph shows what links to what." },
          { id: "dir", left: "Is there a tool for checking one username across many sites?", right: "OSINT Framework", why: "When you don't know which tool you need, a directory organised by category is the place to start." },
        ],
      },
      {
        kind: "anatomy",
        title: "Anatomy of a Domain Record",
        prompt: "Larkhill's own domain, as any stranger can read it. Go through the record field by field. Nothing here asks Larkhill for anything: the answer comes from the registry.",
        source: "WHOIS lookup · larkhillvets.example",
        fields: [
          { key: "Domain Name", value: "LARKHILLVETS.EXAMPLE" },
          { key: "Registrar", value: "Harbour Names Ltd", label: "Sold through", note: "The company the domain was registered through." },
          { key: "Creation Date", value: "2011-04-19T10:22:07Z", label: "Registered", note: "The day the domain was first registered. Subtract it from today for the domain's age." },
          { key: "Updated Date", value: "2026-03-02T08:15:44Z", note: "The last change to this record." },
          { key: "Registry Expiry Date", value: "2029-04-19T10:22:07Z", label: "Paid until", note: "The date the registration runs out." },
          { key: "Name Server", value: "ns1.harbournames.example", label: "Who answers", note: "The servers that answer DNS questions for this domain." },
          { key: "Registrant Organization", value: "REDACTED FOR PRIVACY", label: "Owner", note: "A privacy service has hidden this field." },
        ],
        summary: "A WHOIS record gives a domain's age, registrar, nameservers and expiry. The Linux command is whois, and web front ends such as who.is show the same record.",
      },
      {
        kind: "codebreak",
        title: "Crack the Search Operators",
        prompt: "A stranger needs no special tool to start: a search box will do. Maren wants Larkhill's exposure found the same way, with nothing sent to Larkhill. Crack the operator behind each search.",
        primer: {
          title: "How Search Operators Work",
          points: [
            "An operator is a keyword that narrows a search. It sits before a colon with no space after it: `name:value`.",
            "In a web search engine: `site:` keeps one domain, `filetype:` keeps one kind of document, `intitle:` looks only at the title on the browser tab.",
            "An internet scanner has its own filters: `port:` one port, `org:` the holder of the address block, `hostname:` the names a host reports, `ssl:` the TLS data stored for a host.",
            "Every one of these reads an index somebody else built. The crawler or scanner did its visiting earlier, and your query lands on the index.",
          ],
          example: {
            label: "Narrowing a search on a ferry company's domain",
            lines: [
              "`ferrytimes.example timetable` returns 900 results from anywhere.",
              "`site:ferrytimes.example timetable` returns 40, all on that domain.",
              "`site:ferrytimes.example filetype:pdf timetable` returns 6 PDFs.",
            ],
          },
        },
        rounds: [
          { id: "r1", clue: "Maren types ____:larkhillvets.example and every result now comes from that one domain.", answer: "site", why: "It limits results to one domain. It is the first move of any footprint search, and an attacker starts on you the same way." },
          { id: "r2", clue: "Maren adds ____:xlsx and only spreadsheets come back: the kind somebody put on a web server and forgot.", answer: "filetype", why: "It keeps one document type: xlsx, pdf, docx. Staff lists and client exports on a public server are the classic find." },
          { id: "r3", clue: "Open folders on a web server share one heading. Maren adds ____:\"index of\" so the words must appear in the text on the browser tab.", answer: "intitle", why: "It looks only at the page title. Web servers title an open folder 'Index of /', so this finds folders that list their files to anyone." },
          { id: "r4", clue: "Now the internet scanner. Maren types ____:larkhillvets.example and gets every host whose TLS data carries the group's name, including addresses nobody at Larkhill wrote down.", answer: "ssl", why: "It searches the TLS data the scanner stored for each host, certificate names included. The scanner made those connections earlier, so the search reads its index." },
        ],
        lesson: "Operators turn a search box into a footprint map, and each search here lands on an index somebody else built, never on Larkhill. Going from a name on a certificate to the other hosts carrying it is called certificate pivoting. Anything you find this way about your own company gets reported and taken down, not opened and passed around.",
      },
    ],
    // ── Reading 3: the line ──
    "osint-r3": [
      {
        kind: "spotdiff",
        title: "Find Where the Plan Crosses the Line",
        prompt: "Maren's plan for researching larkhillvets-billing.example, the domain that sent the email, was signed off this morning. A keen contractor has 'improved' a copy. Find the lines that stopped reading and started touching.",
        primer: {
          title: "Passive, Active, and the Legal Line",
          points: [
            "**Passive** collection reads what a third party already holds: a registry, a certificate log, a scanner's index, a web archive. Nothing of yours arrives at the target, so it leaves no trace there.",
            "**Active** collection makes contact with the target's own systems. It appears in their logs, and a watchful operator can react: move, take the server down, or look back at you.",
            "Test any step with one question: **where does this request land?** Passive comes first. Active is only for when the passive sources run out and you have a specific need.",
            "The line is legal as well as practical. Reading what is public is collection. Using a password or a door nobody gave you is unauthorised access, and that stays true on a criminal's server.",
            "Public does not mean free to hoard: personal data stays under privacy law, so keep only what the case needs.",
          ],
          example: {
            label: "Where does it land?",
            lines: [
              "Reading a florist's reviews on a review site lands on the review site. The florist sees nothing.",
              "Ringing the florist to see if the number works lands on the florist. The call shows on their phone.",
              "Same subject, one question, two different answers.",
            ],
          },
        },
        goodTitle: "Maren's signed plan",
        suspectTitle: "The contractor's copy",
        good: [
          "Target: larkhillvets-billing.example, the domain that sent the email",
          "Rule: read what third parties already hold. Nothing of ours lands on its servers",
          "1. WHOIS record: creation date, registrar, nameservers",
          "2. Passive DNS history: past A and MX records",
          "3. Certificate log search: every name logged for the domain",
          "4. Internet scanner record for each address found",
          "5. VirusTotal: reports already on file for each address",
          "6. Web archive: read the snapshots that already exist",
          "7. Paste, breach and C2 tracking indexes such as ThreatFox: any mention of the domain",
          "8. Mailbox names: collect them from the archived pages",
          "9. Write each finding to the case with its source and time",
          "10. Send the blocklist to the mail gateway once Maren signs it",
        ],
        suspect: [
          "Target: larkhillvets-billing.example, the domain that sent the email",
          "Rule: read what third parties already hold. Nothing of ours lands on its servers",
          "1. WHOIS record: creation date, registrar, nameservers",
          "2. dig axfr against its nameserver: pull the whole zone",
          "3. Certificate log search: every name logged for the domain",
          "4. Internet scanner record for each address found",
          "5. VirusTotal: reports already on file for each address",
          "6. Web archive: read every snapshot that already exists, oldest first",
          "7. Paste indexes: take the panel password from the paste and log in to look around",
          "8. Mailbox names: send billing@ a test email and see if it bounces",
          "9. Write each finding to the case with its source, time and analyst",
          "10. Send the blocklist to the mail gateway once Maren signs it",
        ],
        diffs: [
          { line: 3, why: "A zone transfer request lands on the target's own nameserver, and that server can log who asked. Passive DNS answers from a third party's history, so the domain never hears the question." },
          { line: 8, why: "Reading a paste is collection. Logging in is access. Without authorisation that is an offence in most countries, even on a criminal's server, and it can sink the case." },
          { line: 9, why: "A test email is delivered by the target's own mail server, which records where it came from. That is active, however harmless it feels." },
        ],
        decoys: [
          { line: 7, why: "Harmless. The order changed, and it still only reads copies that already exist." },
          { line: 10, why: "Harmless. Better case notes, and nothing leaves the building." },
        ],
        hud: "Tap the lines that stopped reading and started touching",
        sameLine: "That line matches Maren's plan: it reads what a third party holds.",
        winTitle: "The plan is back behind the line",
        howTo: [
          "Compare the contractor's copy with Maren's plan, line by line.",
          "Tap each line where a request lands on the target, or where a step uses access nobody gave you.",
          "Some edits are harmless, and a wrong tap costs a life.",
        ],
        lesson: "Ask one question of every step: where does this request land? On a third party's database it is reading. On the target's own server it is touching, and that needs a reason and a signature. Using something you found to get in is past the line altogether: that is access, not research.",
      },
      {
        kind: "deduce",
        title: "Who Touched the Canary?",
        prompt: "Maren stood up a canary on a Larkhill test name, a page with no job except logging whatever reaches it. Six trainees each researched it a different way this morning. Maren has pulled one visit from its log and reads it out a clue at a time. Whose step made it?",
        primer: {
          title: "The Middle Ground: Active by Proxy",
          points: [
            "Some services go and fetch for you. A **sandbox URL scanner** such as URLScan.io or Any.run opens the page live, in its own browser, from its own address.",
            "The target gets a real visit. It just does not get your address. That is called **active by proxy**, and it sits between reading and touching.",
            "A **canary** is a page that exists only to log what reaches it. Nothing links to it, so every log entry is a real connection.",
            "A web log records the source address, the time, what was requested and the user agent. A browser asks for the page and then for every image and script on it. A one-shot tool asks for one thing.",
            "**Analyst OPSEC** means keeping your identity out of an investigation: a separate VM for investigative browsing, no personal accounts signed in, and intermediary tools that visit on your behalf.",
          ],
          example: {
            label: "Reading one web log entry",
            lines: [
              "`203.0.113.9 - - [04/Nov/2026:09:15:02 +0000] \"GET /menu.html HTTP/1.1\" 200 1840 \"-\" \"curl/8.5.0\"`",
              "Source: 203.0.113.9. Request: one page. User agent: curl.",
            ],
          },
        },
        nameColumn: "Trainee",
        columns: ["What they did", "What they got back", "Working from"],
        suspects: [
          { id: "hart", name: "Hart", cells: ["WHOIS lookup on the domain", "Registrar and dates", "Office"] },
          { id: "osei", name: "Osei", cells: ["Passive DNS history for the name", "One A record from last month", "Office"] },
          { id: "pryce", name: "Pryce", cells: ["curl on the URL", "The page's HTML", "Team VPN"] },
          { id: "tan", name: "Tan", cells: ["Sandbox URL scanner, URL submitted", "Screenshot and request list", "Office"] },
          { id: "varga", name: "Varga", cells: ["Internet scanner record for the address", "Banner from six days ago", "Office"] },
          { id: "wells", name: "Wells", cells: ["Opened the URL in a browser", "The page", "Office"] },
        ],
        clues: [
          "This visit is a real connection to the canary, so the step behind it reached the server itself.",
          "The page's two images and its script were requested in the same second as the page.",
          "The source address belongs to a cloud hosting range. It is not the office, and it is not the VPN exit.",
        ],
        culprit: "tan",
        why: "Tan's step. The sandbox scanner opened the page live in its own browser, from its own cloud address, so the canary logged a full page load from a network that isn't Larkhill's. That is active by proxy. Hart, Osei and Varga read records a third party already held, so the canary has no entry for them. Wells's visit is in the log too, from the office address. Pryce's is one bare request from the VPN exit.",
      },
      {
        kind: "worksheet",
        title: "What Did We Publish?",
        prompt: "Staff have been pasting Larkhill links and files into public scanners to 'check they're safe'. Maren has pulled the last month's list. Work out what those checks gave away.",
        primer: {
          title: "What a Submission Publishes",
          points: [
            "URL scanners offer three visibility settings: **Public** (in the feed and in search, for anyone), **Unlisted** (out of both, readable by vetted security teams), **Private** (your account or team only).",
            "Some URLs contain a secret: a long token that works for whoever holds the link. Anyone who can read that URL can use it, and a stored screenshot shows the page behind it.",
            "A **hash** such as SHA-256 is a one-way fingerprint of a file. A hash search asks whether anyone has reported that fingerprint, and the file stays with you.",
            "An **upload** hands the service the whole file, and public file scanners share uploads with their paying subscribers.",
          ],
          example: {
            label: "One site, two kinds of link",
            lines: [
              "`https://tickets.example/e/spring-concert`: a public event page, with nothing secret in the URL.",
              "`https://tickets.example/t/9Xq2Lm7vPa`: one person's ticket. Whoever holds the link can use it.",
            ],
          },
        },
        caption: "Larkhill staff submissions · last 30 days",
        columns: ["Row", "Service", "Submitted", "Setting", "Who can read it now"],
        rows: [
          ["1", "URL scanner", "https://www.larkhillvets.example/", "Public", "Anyone"],
          ["2", "URL scanner", "https://files.larkhillvets.example/s/k3Vd9QmT2x (client balances)", "Public", "Anyone"],
          ["3", "URL scanner", "https://portal.larkhillvets.example/magic?t=6fb1e2c09a (staff sign-in link)", "Unlisted", "Vetted security teams"],
          ["4", "URL scanner", "https://portal.larkhillvets.example/magic?t=a07d44be13 (staff sign-in link)", "Private", "Larkhill team account"],
          ["5", "File scanner", "locum_rates_2026.pdf, uploaded", "Upload", "Paying subscribers"],
          ["6", "File scanner", "SHA-256 of payroll_summary.pdf, searched", "Search only", "Nobody new"],
        ],
        questions: [
          { id: "out", q: "How many rows put a Larkhill secret or private file in front of readers outside Larkhill?", hint: "The home page was public anyway. For the rest, read what was submitted and the last column.", answer: ["3", "three"], why: "Rows 2, 3 and 5. Row 2 is a working link to client balances, open to anyone. Row 3 is out of the feed, but vetted teams outside Larkhill can still read it. Row 5 is a whole file in subscribers' hands. Row 4 stayed inside Larkhill's account." },
          { id: "hash", q: "Row 6 came back with no reports. Did payroll_summary.pdf leave Larkhill? (yes/no)", hint: "What travelled: the file or its fingerprint?", answer: ["no"], why: "Only the fingerprint travelled, and a fingerprint can't be turned back into the file. No reports means nobody has submitted that file yet." },
        ],
      },
    ],
    // ── Warm-up for the boss: reading a scanner record ──
    "osint-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Scanner Record",
        prompt: "One stop before the live alert. The certificate log listed oldbooking, a host nobody at Larkhill remembers, so Maren pulled its record from an internet scanner. Read it field by field: the alert waiting for you carries the same kind of data.",
        primer: {
          title: "Reading a Scanner Record",
          points: [
            "An internet scanner connected to this address earlier and stored what came back. Reading the record sends nothing to the address.",
            "One record covers one port, and each field answers its own question: who the address block is assigned to, what is running, what name it presents, how the scanner classed it.",
            "**Tor** is an anonymity network. Public, mostly volunteer-run servers called **relays** pass traffic along so that the far end can't see who sent it.",
          ],
          example: {
            label: "One question, one field",
            lines: [
              "Question: which network is this address in?",
              "Field: `asn`, the Autonomous System Number, an identifier for a block of IPs.",
            ],
          },
        },
        source: "Internet scanner · host record · 198.51.100.62:443",
        fields: [
          { key: "ip_str", value: "198.51.100.62", label: "Address" },
          { key: "port", value: "443", note: "The port this record describes. Other open ports have records of their own." },
          { key: "org", value: "Brookfield Hosting Ltd", label: "Assigned to", note: "The organisation the IP space is assigned to." },
          { key: "asn", value: "AS64501", note: "The Autonomous System the address sits in." },
          { key: "os", value: "Windows Server 2008 R2", label: "Detected OS", note: "The scanner's reading of the operating system. It stays empty when the scanner can't tell." },
          { key: "product", value: "Microsoft IIS httpd", label: "What answers", note: "The software named by the service's banner." },
          { key: "version", value: "7.5" },
          { key: "hostnames", value: "[\"oldbooking.larkhillvets.example\"]", note: "The names the scanner holds for this address." },
          { key: "ssl.cert.subject.cn", value: "oldbooking.larkhillvets.example", label: "Certificate name", note: "CN is the Common Name on the TLS certificate. Some tools print it as CN=name. A name starting *. is a wildcard: it covers any single label under that domain." },
          { key: "ssl.cert.expired", value: "true", note: "The certificate's end date has passed, and the server still presents it." },
          { key: "tags", value: "[\"eol-product\"]", label: "Classed as", note: "The scanner's own labels for what this host is, from a fixed list. eol-product means end of life: the vendor no longer supports the software." },
          { key: "timestamp", value: "2026-10-29T03:11:08.412993", label: "Last seen", note: "When the scanner made this connection. The server may have changed since." },
        ],
        summary: "A scanner record is somebody else's visit, written down. This one shows a Larkhill name on a hosted address, on software out of support, and nobody touched the server to learn that. Maren's ticket goes to IT to retire it.",
      },
      {
        kind: "worksheet",
        title: "Same Ports, Different Host",
        prompt: "Maren keeps five scanner records for training. Their os and ports barely differ, and the hosts behind them could not be more different. Read each row, then answer as if a Larkhill laptop had connected.",
        caption: "Internet scanner · five host records · training set",
        columns: ["Row", "os", "Open ports", "tags", "What the tag says", "If a clinic laptop connects"],
        rows: [
          ["1", "Ubuntu 22.04", "22, 443", "cloud", "Hosted at a cloud provider", "Little on its own: much of the web lives in clouds"],
          ["2", "Ubuntu 22.04", "22, 443", "vpn", "Runs a VPN service", "An encrypted tunnel starts at this address"],
          ["3", "Debian 12", "22, 443", "honeypot", "A decoy that records whoever connects", "Nothing real is served here"],
          ["4", "Debian 12", "22, 443", "self-signed", "Its certificate was signed by itself, not a public authority", "Common on lab kit and admin pages: find out what it serves"],
          ["5", "Ubuntu 22.04", "22, 443", "cdn", "An edge server of a content delivery network", "Shared by many sites: the address alone says little"],
        ],
        questions: [
          { id: "field", q: "Rows 1 to 5 read alike on os and ports. Which column decides what each host is?", hint: "Look for the column that changes on every row and comes from the scanner.", answer: ["tags", "tag"], why: "Thousands of small servers share that os and those ports. The tags hold what the scanner concluded about this one, so the same os and ports can be five different hosts." },
          { id: "decoy", q: "A Larkhill laptop opens a session to row 3. Do you close it as routine browsing? (yes/no)", hint: "Who is a decoy built to serve?", answer: ["no"], why: "A decoy serves nobody, so a workstation has no routine reason to reach it. Find the process that opened the session." },
          { id: "tunnel", q: "A Larkhill laptop opens a session to row 2. Can the firewall log show what went through the tunnel? (yes/no)", hint: "What can a firewall see of encrypted traffic?", answer: ["no"], why: "The firewall records the connection and the byte counts, not what runs inside. An unapproved tunnel takes that traffic out of your monitoring, which is why it gets a ticket." },
        ],
      },
    ],
  },
};
