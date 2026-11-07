import type { RoomExperience } from "./types";

// "Operation Breadcrumb" for the "ioc-analysis" room.
// Script: docs/campaign/59-ioc-analysis.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// New task order (the room lists every reading first, so it does not group):
//   ioc-r1, ioc-q1, ioc-q5 | ioc-r2, ioc-q3 | ioc-r3, ioc-q2, ioc-q4 | ioc-la1, ioc-flag1
//
// Kestrel Vale Insurance (fictional), not the graded tasks' corp.example records.
// Signature mechanic: the Pivot Board, a trace lab that starts from one quarantined hash and
// pivots across enrichment sources (sandbox report, passive DNS, WHOIS, scan index, IP
// reputation, communicating files), each step a source table, backed by "tip" evidence screens.
// Game mix: codebreak + hunt + spotdiff.
// Lab data differs from the graded tasks: pain is priced on a share-archiving routine, never
// Office, PowerShell or LSASS (q1), and the Tools example is a loader, never Mimikatz (r1
// checkpoint); staleness is a re-registered domain, never a 14-month-old IP (q5); OPSEC uses a
// spreadsheet and a reset link, never a crafted attachment (r2 checkpoint); the scan index shows
// a certificate on 8443, never port 50050 (q3); reverse passive DNS is one bike shop's two names
// beside a look-alike, never six domains, a bakery or a dentist (q2); the watchlist is sorted by
// control from nine indicators, never a 500-IP feed (q4); the threat intel anatomy is an inbound
// Tor exit hitting a portal, so the source is external, never an outbound laptop, port 443 C2 or
// 3,847 reports (la1, flag1).

const CREW_DOMAINS = ["kv-claimdocs.example", "kv-policyvault.example", "ksv-portal-sync.example"];
const HASH_A = "6cf39050c2fdb47df80790a0d8935b566aa754aeb9880c6cd1b6f014af1d3c13";
const HASH_C = "27a9c8d1a26f2c9e03514df91823102d76e3313a3fd7f99cc28ede3e92119079";
const HASH_EDGE = "12004f8a1bf986fe4b40ce4e4db6175533b28797605f7e93c8550d2f7c19286f";
const HASH_RUNDLL = "6874e8967e49a70f43c69a4f5552320c801ca6c6b2b87b18952820100e5586c8";
const HASH_REGSVR = "8c91dc6ebbcbe5d9c5af80e02aa8fc9ebb88bb8047d12f75df063ce299f34c33";

export const IOC_ANALYSIS: RoomExperience = {
  roomId: "ioc-analysis",
  codename: "Operation Breadcrumb",
  theme: "breadcrumb",
  handler: { name: "Bao Lindgren", role: "Threat Intel Analyst, Kestrel Vale Insurance" },
  briefing: [
    "Kestrel Vale Insurance writes cyber cover for 3,100 small firms, and its policy register says exactly how much each one could claim.",
    "To a ransomware crew that register is a price list: it shows what every victim can afford to pay.",
    "On Tuesday at 08:14 the endpoint agent (EDR) quarantined one file on a claims laptop, and one hash is all Bao Lindgren has to start from.",
    "Learn what an indicator costs an attacker, question the sources without being seen, pivot from one crumb to the whole crew, then make the last call.",
  ],
  mission: "Price indicators by what they cost an attacker, read the sources without tipping your hand, walk the Pivot Board from one hash to a whole crew, hunt every host it touched, then work the last feed match.",
  estimate: "~50 min",
  look: { primary: "#fdba74", secondary: "#67e8f9", warn: "#f43f5e" },
  scene: "facilitybreadcrumb",
  layout: "facility",
  stations: [
    {
      id: "hash",
      label: "The Hash",
      topic: "What IOCs are · the IOC types · the Pyramid of Pain · IOC lifecycle",
      tagline: "One fingerprint. What is it worth?",
      building: "lab",
      taskIds: ["ioc-r1", "ioc-q1", "ioc-q5"],
    },
    {
      id: "sources",
      label: "The Sources",
      topic: "OSINT · VirusTotal · AbuseIPDB · Shodan · URLScan · OTX · MXToolbox · search before you upload",
      tagline: "Ask without being seen",
      building: "archive",
      taskIds: ["ioc-r2", "ioc-q3"],
    },
    {
      id: "board",
      label: "The Pivot Board",
      topic: "IOC pivoting · passive DNS · WHOIS · MISP, STIX and TAXII · watchlists · the IOC quality checklist",
      tagline: "One hash in. A whole crew out.",
      building: "control",
      taskIds: ["ioc-r3", "ioc-q2", "ioc-q4"],
    },
    {
      id: "lastcrumb",
      label: "The Last Crumb",
      topic: "Reading a threat intel match · direction · shared relays · what a pivot cannot tell you",
      tagline: "The feed says high. The case isn't closed.",
      building: "ticket",
      taskIds: ["ioc-la1", "ioc-flag1"],
      boss: true,
    },
  ],
  personas: {
    "ioc-q1": { name: "Bao Lindgren", role: "Threat Intel Analyst", line: "We get one new detection this quarter. Make the case for it." },
    "ioc-q5": { name: "Bao Lindgren", role: "Threat Intel Analyst", line: "An old report just landed in the change queue. What do you do with it?" },
    "ioc-q3": { name: "Bao Lindgren", role: "Threat Intel Analyst", line: "Which source do you open first for this one?" },
    "ioc-q2": { name: "Bao Lindgren", role: "Threat Intel Analyst", line: "Here's the passive DNS. What goes on the board?" },
    "ioc-q4": { name: "Bao Lindgren", role: "Threat Intel Analyst", line: "The feed arrived. Where does it go from here?" },
    "ioc-la1": { name: "Bao Lindgren", role: "Threat Intel Analyst", line: "One more match from the feed. Walk me through it." },
    "ioc-flag1": { name: "Bao Lindgren", role: "Threat Intel Analyst", line: "The network team needs one value from that alert." },
  },
  briefings: {
    // ── Reading 1: IOC types and the Pyramid of Pain ──
    "ioc-r1": [
      {
        kind: "sort",
        title: "Put Each Clue on the Pyramid",
        prompt: "An Indicator of Compromise (IOC) is a piece of evidence that a system was attacked. David Bianco's Pyramid of Pain ranks IOCs by how much it hurts an attacker to lose them. These are Bao's notes from two earlier incidents at other insurers. Bin each one at its level.",
        buckets: [
          { id: "hash", label: "Hash values (trivial)" },
          { id: "ip", label: "IP addresses (easy)" },
          { id: "domain", label: "Domain names (simple)" },
          { id: "artefact", label: "Network/host artefacts (annoying)" },
          { id: "tool", label: "Tools (challenging)" },
          { id: "ttp", label: "TTPs (tough)" },
        ],
        items: [
          { id: "i1", text: "SHA-256 of policy_schedule.dll", bucket: "hash", why: "A hash (MD5, SHA-1, SHA-256) fingerprints one build. Change one byte and it's a new hash, so blocking it stops that file and nothing else." },
          { id: "i2", text: "203.0.113.61, the address the implant called", bucket: "ip", why: "A new server, proxy or VPN exit takes the attacker minutes." },
          { id: "i3", text: "hm-renewals.example, registered for one campaign", bucket: "domain", why: "A new name has to be registered and pointed at a server. A little more work than an address, and still cheap." },
          { id: "i4", text: "Mutex Global\\sync_once_4d1", bucket: "artefact", why: "A mutex is a named object malware creates so it doesn't run twice. It's highly specific, and changing it means changing the tool's code." },
          { id: "i5", text: "URI /api/v2/ping with User-Agent SyncClient/2.1", bucket: "artefact", why: "Traffic patterns are network artefacts. To lose them the crew has to change how the tooling behaves, and test it again." },
          { id: "i6", text: "Run key value CloudSyncHelper under HKCU", bucket: "artefact", why: "Registry keys, file paths and task names are host artefacts: traces left on disk by how the tool installs itself." },
          { id: "i7", text: "A rule that fires on the file name rclone.exe", bucket: "artefact", why: "This looks like tool detection, and it isn't. Rename the file and the rule goes blind. A file name is a host artefact, and a cheap one." },
          { id: "i8", text: "A YARA pattern matching the loader's unpacking code in every build", bucket: "tool", why: "YARA is a pattern-matching rule language. This recognises the tool itself, whatever the build, so the crew must find or write another loader and learn it." },
          { id: "i9", text: "Same TLS certificate on all the crew's servers", bucket: "artefact", why: "An X.509 certificate is a network artefact: an address can move while the certificate comes along, which makes it good to pivot on." },
          { id: "i10", text: "A service account zips a file share, then uploads the archive to cloud storage", bucket: "ttp", why: "That's the way they work, with any tool from any server. Tactics, Techniques and Procedures (TTPs) sit at the top: to escape, the crew has to change its playbook." },
          { id: "i11", text: "Any process that isn't a browser reading a browser's saved-password store", bucket: "ttp", why: "No file, address or tool is named. The rule describes the behaviour, so every tool that does this is caught." },
        ],
      },
      {
        kind: "worksheet",
        title: "What a Block Really Costs the Crew",
        prompt: "A takedown at Harrow Mutual, a peer insurer, recovered this crew's own ledger: every time a defender blocked something, what it cost them to get working again. Bao wants the numbers before anyone argues about which detection to buy.",
        caption: "Recovered ledger · one row per defensive block",
        columns: ["Defender blocked", "Pyramid level", "What the crew did", "Hours lost", "Cost (USD)"],
        rows: [
          ["Loader SHA-256", "Hash values", "Rebuilt with one config byte changed", "0.1", "0"],
          ["C2 (command and control) address", "IP addresses", "Pointed DNS at a spare VPS", "0.5", "6"],
          ["C2 domain", "Domain names", "Registered a new one, new certificate", "2", "14"],
          ["Beacon URI and User-Agent", "Network/host artefacts", "Rewrote the C2 profile, re-tested", "16", "640"],
          ["Every build of the loader", "Tools", "Bought a new loader, retrained", "320", "24000"],
          ["The archive-then-upload routine", "TTPs", "Redesigned how they run an intrusion", "900", "61000"],
        ],
        questions: [
          { id: "q1", q: "How many hours in total did the three bottom levels cost the crew?", hint: "Add Hours lost for the hash, the address and the domain.", answer: ["2.6", "2.6 hours"], why: "2.6 hours for three separate blocks. The crew lost less than a morning, and the attacker's link to the implant was back." },
          { id: "q2", q: "How much money did those three blocks cost them, in USD?", hint: "Add the Cost column for the same three rows.", answer: ["20", "$20", "20 usd"], why: "Twenty dollars. Blocking at the bottom is still worth doing, because it's nearly free for you too, but it doesn't change the crew's month." },
          { id: "q3", q: "How many of the six blocks did they recover from inside one 8-hour working day?", hint: "Count the rows where Hours lost is 8 or less.", answer: ["3", "three"], why: "Three. The artefact block is the first one that took them more than a day, because it forced them to touch their own tooling." },
          { id: "q4", q: "How many times more hours did the TTP block cost than the domain block?", hint: "Divide one Hours lost value by the other.", answer: ["450", "450 times", "450x"], why: "450 times. Bianco's ranks are about effort, and these are one crew's numbers, but the shape is the point: you spend about the same to write either detection, and the attacker's bill is wildly different." },
        ],
      },
      {
        kind: "spotdiff",
        title: "What Did the Crew Bother to Change?",
        prompt: "Harrow Mutual and Marlin Life each sent Bao a sandbox report on what looks like the same loader, a month apart. Tap each line the crew changed between builds. The sandbox's own housekeeping is not the crew's work, so tapping it costs a life.",
        goodTitle: "Build A · Harrow Mutual, September",
        suspectTitle: "Build B · Marlin Life, October",
        hud: "Tap the lines the crew changed",
        sameLine: "That line is the same in both builds.",
        howTo: [
          "Compare Build B with Build A, line by line.",
          "Tap each line in Build B that the crew changed.",
          "A line that matches, or that only the sandbox wrote, costs a life.",
        ],
        good: [
          "sample.type: PE32+ DLL",
          "sha256: 985e0495ae52e3b7c75ffbfaa6430c62297cf70e37d108d248fae66bfc8db589",
          "report.created: 2026-09-21T10:44:07Z",
          "sandbox.vm: win11-x64-07",
          "pe.imphash: b7d2e91f04c6a83d5e1f7720c9a4d6b3",
          "mutex: Global\\sync_once_4d1",
          "persistence: schtasks /create /tn CloudSyncHelper /sc onlogon /tr \"rundll32.exe %APPDATA%\\SyncClient\\cs.dll,Start\"",
          "dns.query: harrow-claimdesk.example",
          "c2.ip: 203.0.113.212",
          "http.uri: /api/v2/ping",
          "http.user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) SyncClient/2.1",
          "behaviour: rundll32 loads the DLL from AppData, beacons every 300 s",
        ],
        suspect: [
          "sample.type: PE32+ DLL",
          "sha256: 9ffadeab25e78b0143d9a3fdb9b661f8a0011f47022b073ea7571f941d35347b",
          "report.created: 2026-10-19T15:02:31Z",
          "sandbox.vm: win11-x64-12",
          "pe.imphash: b7d2e91f04c6a83d5e1f7720c9a4d6b3",
          "mutex: Global\\sync_once_4d1",
          "persistence: schtasks /create /tn CloudSyncHelper /sc onlogon /tr \"rundll32.exe %APPDATA%\\SyncClient\\cs.dll,Start\"",
          "dns.query: marlin-claimdesk.example",
          "c2.ip: 198.51.100.31",
          "http.uri: /api/v2/ping",
          "http.user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) SyncClient/2.1",
          "behaviour: rundll32 loads the DLL from AppData, beacons every 300 s",
        ],
        diffs: [
          { line: 1, why: "New hash, because any rebuild gives one. A hash blocklist from September is already blind to this build." },
          { line: 7, why: "New domain, this time with the victim's name in it: a few dollars and a few minutes." },
          { line: 8, why: "New address. That's three changes, and all three are the bottom of the Pyramid." },
        ],
        decoys: [
          { line: 2, why: "That's when the sandbox wrote its report, not anything the crew did." },
          { line: 3, why: "Which sandbox machine ran the sample. It says nothing about the malware." },
        ],
        lesson: "Three lines changed, and they're the three cheapest things the crew owns. The import hash, mutex, scheduled task, URI, User-Agent and behaviour all survived the rebuild. That's where a detection keeps working on the build you haven't seen yet: look for what they didn't bother to change.",
      },
    ],
    // Drill before q5: an indicator has a shelf life.
    "ioc-q5": [
      {
        kind: "evidence",
        title: "Is This Indicator Still True?",
        prompt: "An IOC has a shelf life, and a feed's verdict doesn't expire on its own. Here are three lookups from Bao's inbox. Check the dates, the sightings and who else uses each one, then say what you're looking at.",
        choices: [
          { id: "live", label: "Live: act on it" },
          { id: "stale", label: "Stale: re-check before acting" },
          { id: "shared", label: "Shared: blocking it breaks others" },
        ],
        items: [
          {
            id: "domain",
            caption: "Intel console · Indicator lookup",
            screen: { type: "tip", indicator: "underwrite-portal.example", kind: "Domain", score: "High confidence · malicious", tags: ["phishing", "report dated January 2026"], sightings: ["Last seen on attacker hosting: 2 February 2026", "Re-registered by a new owner: July 2026", "Now serves a choir's newsletter"] },
            answer: "stale",
            callouts: [
              { at: "score", text: "That verdict was earned in February, and a feed can carry it long after it stopped being true." },
              { at: "sightings", text: "Attackers abandon infrastructure, then someone else gets it. Note first seen and last seen on every IOC, and treat anything older than 3 to 6 months with scepticism until you've found a recent report." },
            ],
          },
          {
            id: "file",
            caption: "Intel console · Indicator lookup",
            screen: { type: "tip", indicator: "44ddf4dbc909688f9be116389856f436dd33a7aa819aa863a1eaf14ef3994101", kind: "SHA-256", score: "High confidence · malicious", tags: ["loader", "3 independent sources"], sightings: ["Seen at a peer insurer 2 days ago", "Sandbox report attached, family named"] },
            answer: "live",
            callouts: [
              { at: "indicator", text: "A file hash can't be reassigned to an innocent owner the way an address can. It fades when the crew rebuilds, and it never turns into someone else's file." },
              { at: "sightings", text: "Recent, several independent sources, and context about what it is. That's what an actionable indicator looks like." },
            ],
          },
          {
            id: "cdn",
            caption: "Intel console · Indicator lookup",
            screen: { type: "tip", indicator: "198.51.100.9", kind: "IPv4", score: "Medium confidence · suspicious", tags: ["content delivery network", "1 campaign"], sightings: ["Last seen yesterday", "Serves about 40,000 unrelated websites", "One campaign fronted a page here"] },
            answer: "shared",
            callouts: [
              { at: "score", text: "It's recent, so it passes the date test. That isn't the only test." },
              { at: "sightings", text: "Block this address and everything behind it breaks, including sites your staff need. Ask whether it could be a false positive before the firewall answers for you. The exact URL or domain is the safer block." },
            ],
          },
        ],
      },
    ],
    // ── Reading 2: the OSINT toolkit ──
    "ioc-r2": [
      {
        kind: "sort",
        title: "Quiet or Loud?",
        prompt: "OSINT (Open-Source Intelligence) is public information, but looking something up can still give you away. The crew may be watching for its own samples. Before Bao's team touches anything, sort these moves: does anybody outside learn you did it?",
        buckets: [
          { id: "quiet", label: "Quiet: nobody learns you looked" },
          { id: "loud", label: "Loud: someone can see it" },
        ],
        items: [
          { id: "a", text: "Search a SHA-256 on a multi-engine scanner", bucket: "quiet", why: "You're asking what others have already submitted. Nothing of yours leaves the building." },
          { id: "b", text: "Upload a Kestrel Vale renewals spreadsheet because its macro looks odd", bucket: "loud", why: "An upload is visible to other subscribers, and that can include the attacker. Here it also hands out client data that was never meant to leave." },
          { id: "c", text: "Read passive DNS history for a domain", bucket: "quiet", why: "It's a record of answers other resolvers already saw. No packet goes to the domain." },
          { id: "d", text: "Read an address's entry in an internet scan index", bucket: "quiet", why: "The index scanned that server earlier. Your lookup reads the index and sends the server nothing." },
          { id: "e", text: "Open the crew's domain in a browser from the office", bucket: "loud", why: "Their web server logs Kestrel Vale's public address, and now they know someone is looking. You may also get served the payload." },
          { id: "f", text: "Run a port scan at the C2 server from the SOC subnet", bucket: "loud", why: "That touches their infrastructure directly, from your own address." },
          { id: "g", text: "Paste a password-reset link, token included, into a public URL scanner", bucket: "loud", why: "Public scan results can be read by anyone, and the token in that link is live. Scan privately, or strip it first." },
          { id: "h", text: "Read the WHOIS record for a domain", bucket: "quiet", why: "Registration data comes from the registry or registrar, not from the attacker's server." },
          { id: "i", text: "Look up an address on a community abuse-report site", bucket: "quiet", why: "You're reading reports other people filed. The address never hears about it." },
        ],
      },
      {
        kind: "match",
        title: "Which Source Answers This Question?",
        prompt: "Each source answers a different question, and the skill is opening the right one first. Bao is stuck on six questions: match each to the tool built for it.",
        pairs: [
          { id: "vt", left: "What do 70-plus antivirus engines and sandboxes say about this file?", right: "VirusTotal", why: "It aggregates engines, sandboxes and blocklists, and takes files, hashes, URLs, IPs and domains. Its Relations tab is where pivoting starts." },
          { id: "abuse", left: "Have other defenders reported this IP, how often, and for what kind of abuse?", right: "AbuseIPDB", why: "Community reports with a 0 to 100% confidence score and categories such as brute force or scanning. Categories describe what people reported, not what the address runs." },
          { id: "urlscan", left: "What does this phishing page load and show, without me clicking it?", right: "URLScan.io", why: "It visits the URL in an isolated browser and records screenshots, HTTP transactions and scripts. A public scan is visible to others." },
          { id: "otx", left: "Has a researcher published a campaign that includes this indicator?", right: "AlienVault OTX", why: "Open Threat Exchange shares pulses: collections of IOCs tied to one campaign or malware family. You can subscribe to them and feed them to a SIEM (Security Information and Event Management platform)." },
          { id: "mx", left: "Who handles mail for this domain, and are SPF, DKIM and DMARC in place?", right: "MXToolbox", why: "Built for email and DNS questions: MX records, spoofing protection, mail server blacklists and WHOIS." },
          { id: "shodan", left: "Which other servers on the internet show this same odd banner?", right: "Shodan", why: "It scans the internet continually and indexes what each device exposes, so you can search by banner to find every server configured the same way." },
        ],
      },
      {
        kind: "anatomy",
        title: "How to Read a Multi-Engine IP Report",
        prompt: "Before anyone quotes a score at Bao, read a report the way Bao does. This address has nothing to do with the case: open each field and see what it can and can't tell you.",
        source: "Multi-engine lookup · IP address report · 198.51.100.187",
        fields: [
          { key: "Detection", value: "11 / 93 security vendors flagged this IP address as malicious", label: "Detection ratio", note: "More vendors means more confidence. A low number on a new server isn't a clean bill of health, though: engines need time to catch up." },
          { key: "Last Analysis Date", value: "2026-03-30 06:12:44 UTC", label: "How old", note: "Read this before the ratio. This report is seven months old, so the address may have a new tenant by now." },
          { key: "Community Score", value: "-23", label: "The crowd", note: "User votes, not engine verdicts. A negative score means voters call it malicious. Useful, and easier to game than an engine." },
          { key: "AS Owner", value: "Tarnbrook VPS Ltd (AS64511)" },
          { key: "Country", value: "NL" },
          { key: "Relations · Passive DNS Replication", value: "6 domains", label: "Who pointed here", note: "Passive DNS is a history of the domains that have resolved to this address. This is where a pivot begins." },
          { key: "Relations · Communicating Files", value: "3 files", label: "What called here", note: "Malware samples that phoned home to this address, each with a hash you can search for on your own endpoints." },
        ],
        summary: "A report is a set of questions, not a verdict. How many vendors, how recently, what does the crowd say, who owns the address, and what else is related to it? The ratio tells you how worried to be. The Relations tab tells you where to go next.",
      },
    ],
    // ── Reading 3: pivoting and operationalising IOCs ──
    "ioc-r3": [
      {
        kind: "trace",
        title: "The Pivot Board",
        prompt: "Pivoting means using one indicator to find the ones connected to it. Start from the hash the EDR quarantined. Each step opens a different source: click the row that answers Bao's question, and the case board fills in the crew, one pivot at a time.",
        lead: "SHA-256 6cf39050...1d3c13, quarantined on KV-CL-LT22, Tue 3 Nov 08:14",
        steps: [
          {
            id: "sandbox",
            ask: "Hash to sandbox: the sample ran for five minutes. Which row is the sample itself calling out, not Windows keeping busy?",
            source: "Sandbox report · Network activity",
            columns: ["t+ (s)", "Process", "Protocol", "Host", "Request"],
            rows: [
              ["2", "svchost.exe", "DNS", "time.osvendor.example", "A query, time sync"],
              ["6", "svchost.exe", "HTTPS", "ctl.osvendor.example", "GET /certs/trustlist.cab"],
              ["9", "rundll32.exe", "HTTP", "ocsp.certissuer.example", "POST /, OCSP check on a signature"],
              ["11", "rundll32.exe", "HTTPS", "kv-claimdocs.example", "GET /api/v2/ping, User-Agent SyncClient/2.1"],
              ["14", "svchost.exe", "DNS", "wpad.sandbox.example", "A query, proxy auto-discovery"],
            ],
            answer: 3,
            why: "rundll32.exe talking to a domain with Kestrel Vale's initials in it, on a fixed URI. The OCSP (certificate status) row is the same process, but it's only a certificate check. You've moved from a file, which changes with one byte, to infrastructure the crew has to pay for.",
            learned: "C2 domain: kv-claimdocs.example",
          },
          {
            id: "pdns",
            ask: "Domain to passive DNS: this domain has had more than one answer. Where does it point today?",
            source: "Passive DNS · forward lookup · kv-claimdocs.example",
            columns: ["rrname", "rrtype", "rdata", "time_first", "time_last", "count"],
            rows: [
              ["kv-claimdocs.example", "A", "203.0.113.88", "2026-10-28", "2026-11-03", "1906"],
              ["kv-claimdocs.example", "A", "198.51.100.52", "2026-10-26", "2026-10-27", "41"],
              ["kv-claimdocs.example", "NS", "ns1.parkdns.example", "2026-10-26", "2026-11-03", "214"],
              ["www.kv-claimdocs.example", "CNAME", "kv-claimdocs.example", "2026-10-28", "2026-11-02", "37"],
            ],
            answer: 0,
            why: "Passive DNS records what resolvers really saw, and time_first and time_last bracket each answer. The other A record ended on 27 Oct: that was the registrar's parking page. Read the dates on every row, because a list like this is history, not the current state.",
            learned: "Points at 203.0.113.88 since 28 Oct",
          },
          {
            id: "whois",
            ask: "Domain to WHOIS: which field is the strongest sign this domain was made for this campaign?",
            source: "WHOIS · kv-claimdocs.example",
            columns: ["Field", "Value"],
            rows: [
              ["Domain Name", "KV-CLAIMDOCS.EXAMPLE"],
              ["Registrar", "Tallow Names Ltd"],
              ["Updated Date", "2026-10-28T09:12:03Z"],
              ["Creation Date", "2026-10-26T21:47:55Z"],
              ["Registrant Organization", "REDACTED FOR PRIVACY"],
              ["Name Server", "NS1.PARKDNS.EXAMPLE"],
              ["DNSSEC", "unsigned"],
            ],
            answer: 3,
            why: "Created eight days before the quarantine. The redacted registrant proves nothing: most registrars have redacted that field by default since GDPR, so honest domains look the same. Age is the signal.",
            learned: "Registered 26 Oct, 8 days before the quarantine",
          },
          {
            id: "rpdns",
            ask: "IP to passive DNS, in reverse: other names have pointed at this address. Which one should you pivot on next?",
            source: "Passive DNS · reverse lookup · 203.0.113.88",
            columns: ["rrname", "rrtype", "rdata", "time_first", "time_last", "count"],
            rows: [
              ["kv-claimdocs.example", "A", "203.0.113.88", "2026-10-28", "2026-11-03", "1906"],
              ["kv-policyvault.example", "A", "203.0.113.88", "2026-10-29", "2026-11-03", "624"],
              ["pedalworks-repairs.example", "A", "203.0.113.88", "2024-02-11", "2024-09-30", "3180"],
              ["mail.pedalworks-repairs.example", "A", "203.0.113.88", "2024-02-11", "2024-09-30", "412"],
              ["88.113.0.203.in-addr.arpa", "PTR", "vps-88.tarnbrook-hosting.example", "2024-01-19", "2026-11-03", "52"],
            ],
            answer: 1,
            why: "Same week, same naming pattern, still live. The bike shop has the biggest count and left two years ago: it was an earlier tenant of a rented server. A name on an address is a lead, and the dates decide whether it's a relative.",
            learned: "Sibling domain: kv-policyvault.example",
          },
          {
            id: "scan",
            ask: "IP to scan index: the address will change one day. Which service exposes something the crew is likely to carry to the next server?",
            source: "Shodan-style host lookup · 203.0.113.88",
            columns: ["port", "transport", "product", "ssl.cert.subject.cn", "ssl.cert.serial", "http.title"],
            rows: [
              ["22", "tcp", "OpenSSH 8.9", "-", "-", "-"],
              ["80", "tcp", "nginx", "-", "-", "301 Moved Permanently"],
              ["443", "tcp", "nginx", "kv-claimdocs.example", "03a1f7c2d9", "Document Portal"],
              ["8443", "tcp", "-", "panel.internal", "4f2a9c17e03b", "404 Not Found"],
              ["9100", "tcp", "Prometheus Node Exporter", "-", "-", "-"],
            ],
            answer: 3,
            why: "A scan index shows what a server exposes, read without sending it a packet. A self-signed certificate on an admin port was set up by hand, and crews reuse it. That's a network artefact, two levels above the address. Searching the serial across the index turns up a second server.",
            learned: "Same certificate on 198.51.100.140, serving ksv-portal-sync.example",
          },
          {
            id: "rep",
            ask: "IP to reputation: the sandbox run and the certificate search left four addresses on the board. Which one is a server the crew runs alone?",
            source: "IP reputation lookup · addresses on the board",
            columns: ["ipAddress", "abuseConfidenceScore", "totalReports", "usageType", "isp", "isTor", "lastReportedAt"],
            rows: [
              ["198.51.100.223", "100", "2411", "Data Center/Web Hosting/Transit", "Open Relay Collective", "true", "2026-11-03"],
              ["198.51.100.212", "0", "6", "Content Delivery Network", "Larkspur Edge Networks", "false", "2026-09-14"],
              ["198.51.100.140", "4", "2", "Data Center/Web Hosting/Transit", "Tarnbrook VPS Ltd", "false", "2026-11-01"],
              ["203.0.113.19", "61", "97", "Fixed Line ISP", "Fernhill Broadband", "false", "2026-10-30"],
            ],
            answer: 2,
            why: "Score 4 from two reports, on a small hosting provider, and tied to the crew by that certificate. A score counts reports, not guilt, and a new server hasn't had time to collect any. The Tor relay's 100 is other people's abuse, the CDN edge serves thousands of sites, and the home line is probably one compromised router.",
            learned: "Dedicated: 198.51.100.140. The Tor relay, CDN edge and home line stay off the blocklist",
          },
          {
            id: "files",
            ask: "IP to files: which sample is from this campaign, and gives you the next hash to search for inside Kestrel Vale?",
            source: "Relations · Communicating files · 198.51.100.140",
            columns: ["sha256", "type", "detections", "first_submission", "names"],
            rows: [
              ["27a9c8d1...119079", "Win32 DLL", "9/71", "2026-10-30", "claim_form_update.dll"],
              ["3d81f2ab...60c7e4", "Win32 EXE", "58/71", "2024-06-12", "svcupdate.exe"],
              ["a4c07e11...92be08", "Android APK", "22/71", "2025-12-19", "bank_sec.apk"],
              ["5de3b6f0...7711c2", "HTML", "3/71", "2026-03-02", "login.html"],
            ],
            answer: 0,
            why: "Same type as your sample, same week as the domains. 58 of 71 looks more convincing, but that file is from 2024, before this crew rented the address. Detections rise with age, so a fresh build scores low. One hash in, more hashes out, and now you have a set to take back inside.",
            learned: "Sibling build: 27a9c8d1...119079",
          },
        ],
      },
      {
        kind: "hunt",
        title: "Find Every Host That Touched the Crew",
        prompt: "The board gave you three domains. Now turn them inward. The question from the CISO, Kestrel Vale's security chief, is one line: which Kestrel Vale hosts touched any of them? Build the query one line at a time. Every result you see is really what that line returns.",
        language: "KQL",
        start: "DeviceNetworkEvents",
        goal: "one row for each host that touched the crew",
        tables: [
          {
            name: "DeviceNetworkEvents",
            note: "Network connections per device. RemoteUrl is blank when the sensor can't read the name, so a real hunt checks RemoteIP too.",
            columns: ["Timestamp", "DeviceName", "ActionType", "RemoteIP", "RemotePort", "RemoteUrl", "InitiatingProcessFileName", "InitiatingProcessCommandLine", "InitiatingProcessSHA256"],
            rows: [
              ["11-02 16:41", "kv-uw-lt03", "ConnectionFailed", "203.0.113.88", "443", "kv-policyvault.example", "rundll32.exe", "rundll32.exe C:\\Users\\t.okoye\\AppData\\Local\\Temp\\renewal_terms.dll,Start", HASH_RUNDLL],
              ["11-02 17:10", "kv-cl-lt07", "ConnectionSuccess", "198.51.100.140", "8443", "ksv-portal-sync.example", "regsvr32.exe", "regsvr32.exe /s C:\\Users\\r.pryce\\AppData\\Local\\Temp\\claim_form_update.dll", HASH_REGSVR],
              ["11-02 17:25", "kv-cl-lt07", "ConnectionSuccess", "198.51.100.140", "8443", "ksv-portal-sync.example", "regsvr32.exe", "regsvr32.exe /s C:\\Users\\r.pryce\\AppData\\Local\\Temp\\claim_form_update.dll", HASH_REGSVR],
              ["11-03 07:58", "kv-hr-lt05", "ConnectionSuccess", "10.40.0.20", "443", "portal.kestrelvale.example", "msedge.exe", "msedge.exe", HASH_EDGE],
              ["11-03 08:05", "kv-cl-lt22", "ConnectionSuccess", "10.40.0.21", "443", "claims.kestrelvale.example", "msedge.exe", "msedge.exe", HASH_EDGE],
              ["11-03 08:12", "kv-cl-lt22", "ConnectionSuccess", "203.0.113.88", "443", "kv-claimdocs.example", "rundll32.exe", "rundll32.exe C:\\Users\\m.ferro\\AppData\\Local\\Temp\\policy_schedule.dll,Start", HASH_RUNDLL],
              ["11-03 08:13", "kv-cl-lt22", "ConnectionSuccess", "203.0.113.88", "443", "kv-claimdocs.example", "rundll32.exe", "rundll32.exe C:\\Users\\m.ferro\\AppData\\Local\\Temp\\policy_schedule.dll,Start", HASH_RUNDLL],
              ["11-03 08:44", "kv-it-wk02", "ConnectionSuccess", "198.51.100.200", "443", "updates.fontvendor.example", "svchost.exe", "svchost.exe -k netsvcs", "b1f6c2a04d7e953a86c0f2e7d4193a5ec76d08f2ba4e91c3d5a07f6e2c81b49d"],
              ["11-03 09:02", "kv-soc-sbx01", "ConnectionSuccess", "203.0.113.88", "443", "kv-claimdocs.example", "rundll32.exe", "rundll32.exe C:\\Analysis\\policy_schedule.dll,Start", HASH_RUNDLL],
              ["11-03 10:12", "kv-fin-lt11", "ConnectionSuccess", "203.0.113.88", "443", "kv-policyvault.example", "msedge.exe", "msedge.exe https://kv-policyvault.example/renewal", HASH_EDGE],
            ],
          },
          {
            name: "DeviceInfo",
            note: "Device inventory. Here one row per device; a real tenant has many reports for each.",
            columns: ["DeviceName", "OSPlatform", "MachineGroup", "PublicIP"],
            rows: [
              ["kv-cl-lt07", "Windows11", "Claims", "198.51.100.6"],
              ["kv-cl-lt22", "Windows11", "Claims", "198.51.100.6"],
              ["kv-uw-lt03", "Windows11", "Underwriting", "198.51.100.6"],
              ["kv-fin-lt11", "Windows11", "Finance", "198.51.100.6"],
              ["kv-hr-lt05", "Windows11", "HR", "198.51.100.6"],
              ["kv-it-wk02", "Windows11", "IT", "198.51.100.6"],
              ["kv-soc-sbx01", "Windows11", "SOC lab", "198.51.100.7"],
            ],
          },
          {
            name: "DeviceFileEvents",
            note: "Files created, changed, deleted.",
            columns: ["Timestamp", "DeviceName", "FileName", "FolderPath", "SHA256", "ActionType"],
            rows: [
              ["11-02 17:08", "kv-cl-lt07", "claim_form_update.dll", "C:\\Users\\r.pryce\\AppData\\Local\\Temp\\claim_form_update.dll", HASH_C, "FileCreated"],
              ["11-03 08:12", "kv-cl-lt22", "policy_schedule.dll", "C:\\Users\\m.ferro\\AppData\\Local\\Temp\\policy_schedule.dll", HASH_A, "FileCreated"],
              ["11-03 08:12", "kv-cl-lt22", "schedule_cover.pdf", "C:\\Users\\m.ferro\\Downloads\\schedule_cover.pdf", "3ea5e896e9c953909ef6c53a914382d89dd97665dd96ce78df41a5a80b82569d", "FileCreated"],
              ["11-03 08:14", "kv-cl-lt22", "policy_schedule.dll", "C:\\Users\\m.ferro\\AppData\\Local\\Temp\\policy_schedule.dll", HASH_A, "FileDeleted"],
            ],
          },
        ],
        rungs: [
          {
            id: "set", ask: "Line 2: search for what the board found. Which filter finds every host?",
            choices: [
              { id: "a", text: '| where InitiatingProcessCommandLine has "policy_schedule.dll"', why: "Only the laptop you already knew about, and your own sandbox. The crew gave each victim its own file name and build, so the one you started with can't see the others. InitiatingProcessSHA256 won't help either: it's the hash of rundll32.exe, not of the DLL it loaded.", apply: { op: "where", col: "InitiatingProcessCommandLine", test: "has", value: "policy_schedule.dll" } },
              { id: "b", text: '| where RemoteIP == "203.0.113.88"', why: "One server. kv-cl-lt07 called the crew's second server, so this misses it. An address is one of the cheapest things they own, and they had two.", apply: { op: "where", col: "RemoteIP", test: "eq", value: "203.0.113.88" } },
              { id: "c", text: `| where RemoteUrl in~ ("${CREW_DOMAINS.join('", "')}")`, right: true, why: "The whole set the pivot gave you. in~ matches any item in the list and ignores case. Seven rows, on five hosts so far.", apply: { op: "where", col: "RemoteUrl", test: "in", value: CREW_DOMAINS } },
              { id: "d", text: '| where RemoteUrl contains "claim"', why: "A keyword caught your own claims portal and missed two of the crew's domains. Hunt on the exact indicators, not on what they sound like.", apply: { op: "where", col: "RemoteUrl", test: "has", value: "claim" } },
            ],
          },
          {
            id: "noise", ask: "Line 3: one of these results isn't a victim. Take out what doesn't belong.",
            choices: [
              { id: "a", text: '| where ActionType == "ConnectionSuccess"', why: "That dropped kv-uw-lt03: the connection failed, whatever stopped it. A failed beacon still means an implant is running on that laptop. It's a victim you nearly lost.", apply: { op: "where", col: "ActionType", test: "eq", value: "ConnectionSuccess" } },
              { id: "b", text: '| where InitiatingProcessFileName =~ "rundll32.exe"', why: "That dropped kv-cl-lt07, whose loader ran through regsvr32, and kv-fin-lt11, where someone clicked the link in a browser. The question is who touched the crew, not how.", apply: { op: "where", col: "InitiatingProcessFileName", test: "ieq", value: "rundll32.exe" } },
              { id: "c", text: '| where DeviceName !in~ ("kv-soc-sbx01")', right: true, why: "That's your own SOC sandbox, detonating the sample on purpose. Analysts and their tools touch indicators too, so exclude them by name, and keep the list short and known.", apply: { op: "where", col: "DeviceName", test: "notin", value: ["kv-soc-sbx01"] } },
            ],
          },
          {
            id: "who", ask: "Line 4: Bao has to call each department. This table doesn't say whose device it is.",
            choices: [
              { id: "a", text: "| join kind=inner DeviceInfo on DeviceName", right: true, why: "Device inventory, matched on the device. Every row now carries MachineGroup, so you can see Claims, Underwriting and Finance.", apply: { op: "join", table: "DeviceInfo", left: "DeviceName", right: "DeviceName" } },
              { id: "b", text: "| join kind=inner DeviceInfo on $left.RemoteIP == $right.PublicIP", why: "No results. RemoteIP is the far end of the connection, the crew's server, and PublicIP is your own office's address. Those two never match.", apply: { op: "join", table: "DeviceInfo", left: "RemoteIP", right: "PublicIP" } },
              { id: "c", text: "| join kind=inner DeviceFileEvents on DeviceName", why: "Rows multiplied per file, and kv-uw-lt03 and kv-fin-lt11 vanished: an inner join drops any host with nothing on the other side. They still touched the crew. And it doesn't say whose device it is.", apply: { op: "join", table: "DeviceFileEvents", left: "DeviceName", right: "DeviceName" } },
            ],
          },
          {
            id: "scope", ask: "Line 5: the answer has to be one line per host, not one per connection.",
            choices: [
              { id: "a", text: "| summarize count() by RemoteUrl", why: "That counts each domain. Useful for the report, but the question is hosts.", apply: { op: "summarize", by: ["RemoteUrl"] } },
              { id: "b", text: "| project DeviceName, RemoteUrl, MachineGroup", why: "The right columns, and still one row per connection, so kv-cl-lt22 appears twice. Someone reading this would count six victims.", apply: { op: "project", cols: ["DeviceName", "RemoteUrl", "MachineGroup"] } },
              { id: "c", text: "| summarize count() by DeviceName, MachineGroup", right: true, why: "Four hosts in three departments, including one whose connection failed, whatever stopped it. You started with one laptop.", apply: { op: "summarize", by: ["DeviceName", "MachineGroup"] } },
            ],
          },
        ],
        expect: 4,
        lesson: "Hunt the whole set the pivot gave you, not just the indicator you started with, and not by one file's name or hash. Take out your own tooling and keep failed connections in: a blocked beacon still proves an implant, which is why a watchlist has to alert as well as block. In a real tenant, add a Timestamp limit from the indicators' first seen dates, check RemoteIP as well as RemoteUrl, and take the latest DeviceInfo row with arg_max before you join.",
      },
      {
        kind: "codebreak",
        title: "Crack the Sharing Terms",
        prompt: "Kestrel Vale is joining the insurers' sharing group today, and what Bao found has to reach them in a form machines can read. Crack each term from its clue. Green is the right place, amber is in the word.",
        rounds: [
          { id: "platform", clue: "The open-source platform where CERTs and ISACs (Information Sharing and Analysis Centers) swap IOCs.", answer: "MISP", why: "Malware Information Sharing Platform & Threat Sharing. Government CERTs (Computer Emergency Response Teams), ISACs and large firms use it with their partners." },
          { id: "report", clue: "On that platform, the word for one report about an incident or campaign. The IOCs inside it are called Attributes.", answer: "EVENT", why: "An Event holds Attributes, the actual hashes, IPs and domains, and is tagged with ATT&CK techniques, threat actor names and sector." },
          { id: "language", clue: "A JSON-based language that describes threat intelligence so a machine can read it.", answer: "STIX", why: "Structured Threat Information eXpression. It's the format of the message, not the way it travels." },
          { id: "transport", clue: "The protocol that carries that JSON between servers.", answer: "TAXII", why: "Trusted Automated eXchange of Intelligence Information. MISP and most SIEMs support STIX over TAXII, and CSV remains the simple fallback for an import." },
        ],
        lesson: "Keep the two apart: STIX is what you say and TAXII is how it gets there. MISP is where a community keeps it, as Events full of Attributes. An IOC only protects the next company if a machine at the other end can load it.",
      },
      {
        kind: "sort",
        title: "Where Does Each Indicator Go?",
        prompt: "The board is done and Bao is writing the change request. Send each indicator to the control that can use it. Anything that fails the quality checklist (is it recent, is it confident, could it be a false positive, is there context?) stays off the list.",
        buckets: [
          { id: "net", label: "Firewall + SIEM" },
          { id: "dns", label: "DNS sinkhole + SIEM" },
          { id: "edr", label: "EDR hash watchlist" },
          { id: "no", label: "Keep off the list" },
        ],
        items: [
          { id: "a", text: "203.0.113.88, the crew's rented server, live today", bucket: "net", why: "The firewall stops the outbound connection and the SIEM raises an alert the moment a host tries. Block alone is silent, and you'd never learn which host is infected." },
          { id: "b", text: "kv-policyvault.example, first seen 29 Oct", bucket: "dns", why: "A DNS firewall or sinkhole stops the lookup. Keep it in the SIEM too, because the alert is what tells you who asked." },
          { id: "c", text: "SHA-256 6cf39050...1d3c13, the loader build", bucket: "edr", why: "The EDR alerts when any endpoint runs a matching file. It's the bottom of the Pyramid, and loading it costs you nothing." },
          { id: "d", text: "ksv-portal-sync.example, found through the certificate", bucket: "dns", why: "A domain goes to the same place however you found it. Matches should alert as they happen, not wait for a monthly review." },
          { id: "e", text: "SHA-256 27a9c8d1...119079, the sibling build", bucket: "edr", why: "The pivot paid off here: a hash nobody at Kestrel Vale had seen before the board found it." },
          { id: "f", text: "198.51.100.140, tied to the crew by its certificate", bucket: "net", why: "A dedicated server, recent, with a link you can explain. It passes all four checks." },
          { id: "g", text: "A CDN edge address the sample fetched a script from", bucket: "no", why: "Could it be a false positive? Yes: thousands of sites sit behind it. Block the exact URL instead." },
          { id: "h", text: "A hash from an anonymous paste, one source, no malware family", bucket: "no", why: "One source and no context. You couldn't tell a responder what a match means, so it isn't actionable yet." },
          { id: "i", text: "A domain from a report 11 months old, no sightings since March", bucket: "no", why: "Older than 3 to 6 months. Old infrastructure changes hands. Find fresh sightings before it goes on a list." },
        ],
      },
    ],
    // ── Before the boss: reading a feed match ──
    "ioc-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Threat Intel Match",
        prompt: "The board is closed and the feed is now watching for you. This match came in overnight on Kestrel Vale's broker portal, and it was harmless in the end. Open each field: every one answers a different question, and none of them answers all of it.",
        source: "SIEM alert · threat_intel_match · kv-broker-web1",
        fields: [
          { key: "data.srcip", value: "203.0.113.130", label: "Who started it", note: "The source is always the side that opened the connection, whichever side is yours. Here an outside address reached in. Read direction before you read anything else." },
          { key: "data.dstip", value: "10.60.2.15", label: "Who it reached", note: "The destination: the portal server, in Kestrel Vale's private address range." },
          { key: "data.dstport", value: "443" },
          { key: "data.proto", value: "tcp" },
          { key: "threat_intel.indicator", value: "203.0.113.130" },
          { key: "threat_intel.category", value: "Tor Exit Node", label: "What the address is", note: "Tor is an anonymity network: traffic crosses three relays, guard, middle and exit. A client connects out to its guard, and a website only ever sees the exit. So an exit in the source field means someone is arriving through Tor. The label describes the address, not the person." },
          { key: "threat_intel.confidence", value: "98", label: "Feed confidence", note: "How sure the feed is about its label. It isn't a measure of how likely your host is to be compromised." },
          { key: "threat_intel.source", value: "AbuseIPDB" },
          { key: "threat_intel.report_count", value: "2176", label: "Abuse reports", note: "Everyone who complained about traffic from this relay. On a shared relay those reports describe its other users, so they say nothing about this visitor." },
          { key: "threat_intel.last_reported", value: "2026-11-03", label: "How fresh" },
        ],
        summary: "A match tells you an address is known, not what happened. Take direction from the source field, take what the address is from the category, and be careful what you infer from the counts. The next question is always one the feed can't answer: what, on your side, made this connection?",
      },
      {
        kind: "evidence",
        title: "Whose Address Is This?",
        prompt: "A pivot works when the infrastructure belongs to the attacker. Before Bao spends an afternoon on an address, Bao asks who else uses it. Here are three lookups: say what each address really is.",
        choices: [
          { id: "own", label: "Attacker's own server" },
          { id: "relay", label: "Anonymising relay or VPN exit" },
          { id: "shared", label: "Shared hosting" },
        ],
        items: [
          {
            id: "vpn",
            caption: "Intel console · Indicator lookup",
            screen: { type: "tip", indicator: "198.51.100.174", kind: "IPv4", score: "High confidence · malicious", tags: ["1,930 abuse reports", "last seen today"], sightings: ["Commercial VPN exit with thousands of paying customers", "Reports cover brute force, scraping and spam, from many unrelated users", "Relations: 300+ unrelated domains and samples"] },
            answer: "relay",
            callouts: [
              { at: "score", text: "The score is real, and it's about strangers. Many people leave through this exit, so its record belongs to all of them." },
              { at: "sightings", text: "Pivoting here mixes unrelated people's samples and domains. When the address is shared, go back to the endpoint: which process on your host made the connection?" },
            ],
          },
          {
            id: "vps",
            caption: "Intel console · Indicator lookup",
            screen: { type: "tip", indicator: "203.0.113.154", kind: "IPv4", score: "Medium confidence · malicious", tags: ["self-signed certificate", "first seen 12 days ago"], sightings: ["One small hosting customer, no other domains in 12 months", "Two hosts at a peer insurer beacon to it on TCP 80 every 60 seconds"] },
            answer: "own",
            callouts: [
              { at: "indicator", text: "One customer, one purpose. This is the kind of address where passive DNS and communicating files really do lead somewhere." },
              { at: "sightings", text: "Port 80 proves nothing. Attackers pick a port your egress rules already allow, so the traffic looks routine, and most C2 frameworks can be set to almost any port. A strange high port stands out; a common one doesn't, so you inspect the content, not the port." },
            ],
          },
          {
            id: "host",
            caption: "Intel console · Indicator lookup",
            screen: { type: "tip", indicator: "198.51.100.46", kind: "IPv4", score: "Low confidence · suspicious", tags: ["web hosting provider", "last seen 3 days ago"], sightings: ["Hosts 1,900 small-business websites", "One phishing kit was reported on one of them"] },
            answer: "shared",
            callouts: [
              { at: "score", text: "Low, and honest about it: one tenant out of 1,900 was reported." },
              { at: "sightings", text: "The IOC here is the one site's URL. The address is a neighbourhood, so pivoting on it brings you 1,899 innocent neighbours." },
            ],
          },
        ],
      },
    ],
  },
};
