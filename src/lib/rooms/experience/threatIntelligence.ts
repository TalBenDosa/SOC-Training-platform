import type { RoomExperience } from "./types";

// "Operation Diamond" for the "threat-intelligence" room.
// Script: docs/campaign/82-threat-intelligence.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Penrose Energy (fictional), not the graded tasks' CORP-DC01 records.
// Signature: Fill the Diamond. A vendor report and a pile of raw notes become one Diamond Model
// event (a sort), and the room works one stakeholder's question round the intelligence lifecycle:
// a feed nobody asked for is data. Room 59 owns IOC pivoting, so nothing here pivots on an indicator.
// Game mix: codebreak + duel + rush.
//
// Task order changed. The room had all readings first and flag1 before q4 and q5, so it could not
// split into stations. New order, which keeps flag1 straight after la1 because it says "the alert above":
//   r1, q1 | r2, q4, q5 | q2 | r3, q3 | la1, flag1
//
// Lab data differs from the graded tasks. The strategic reader is a Head of Strategy weighing a
// deal, not a board setting a budget (q1). Feedback is about what a page should name next time,
// not stale IPs (r1 checkpoint). The sector peer source is E-ISAC for energy, not a hospital (q5).
// The two-way exchange is three neighbouring utilities, not a CERT's invitation (q4). The alias
// questions use Voodoo Bear, APT44, Wicked Panda and Vanguard Panda, never Fancy Bear with APT29
// (q2); the crosswalk shows the graded recall facts only as data in rows, and never asks them
// (q2, flag1). No card asks about plain TLP:AMBER: it appears as a labelled line in the primer, and
// the cards test the other levels (q3). The hit is on a jump host with a medium-confidence domain,
// every 15 minutes, not a domain controller with a high-confidence IP every 5 minutes (la1).
// Containment is an egress rule on a jump host agreed with grid operations, with no krbtgt (la1).

export const THREAT_INTELLIGENCE: RoomExperience = {
  roomId: "threat-intelligence",
  codename: "Operation Diamond",
  theme: "diamond",
  handler: { name: "Callista Nwosu", role: "Threat Intel Lead, Penrose Energy" },
  briefing: [
    "Penrose Energy. Gas and power for 640,000 homes across three counties, and the winter peak starts in five weeks.",
    "Ingrid Solheim runs grid operations and has one question: can the crew that hit Aldermoor Gas last month reach our substation engineers, and should the vendor support sessions stop before the peak?",
    "The threat feed pours 48,000 indicators a day into the SOC. Callista Nwosu has nine days to say which ones matter.",
    "Take one real question the whole way round: collect for it, fill the Diamond, release it under the right label, and act when the first hit lands.",
  ],
  mission: "Turn a stakeholder's question into a requirement, work it round the intelligence lifecycle, pick the sources that can answer it, fill one Diamond Model event from a vendor report and raw notes, release it under the right label, then prove the first hit with your own logs.",
  estimate: "~55 min",
  look: { primary: "#9be7ff", secondary: "#f2c14e", warn: "#ff5a7a" },
  scene: "facilitydiamond",
  layout: "facility",
  stations: [
    {
      id: "requirement",
      label: "The Requirement",
      topic: "Information and intelligence · the intelligence lifecycle · the four types of CTI",
      tagline: "Who asked, and what will they decide?",
      building: "office",
      taskIds: ["threat-intel-r1", "threat-intel-q1"],
    },
    {
      id: "collection",
      label: "The Collection",
      topic: "Threat actor categories · ISACs · MISP · open and commercial feeds · STIX and TAXII",
      tagline: "Ask the source that can answer",
      building: "archive",
      taskIds: ["threat-intel-r2", "threat-intel-q4", "threat-intel-q5"],
    },
    {
      id: "diamond",
      label: "The Diamond",
      topic: "APT naming conventions · ATT&CK Group IDs · the Diamond Model",
      tagline: "Four corners, one event",
      building: "lab",
      taskIds: ["threat-intel-q2"],
    },
    {
      id: "release",
      label: "The Release",
      topic: "TLP 2.0 · confidence · IOC matching · hunting · enrichment · detection engineering",
      tagline: "Who may read it, and what changes?",
      building: "control",
      taskIds: ["threat-intel-r3", "threat-intel-q3"],
    },
    {
      id: "firsthit",
      label: "The First Hit",
      topic: "Validating an IOC match · containing a live channel · finding an ATT&CK Group ID",
      tagline: "The feed matched. Now prove it.",
      building: "ticket",
      taskIds: ["threat-intel-la1", "threat-intel-flag1"],
      boss: true,
    },
  ],
  personas: {
    "threat-intel-q1": { name: "Callista Nwosu", role: "Threat Intel Lead", line: "This one came down from the top floor. Think about who is reading it." },
    "threat-intel-q4": { name: "Callista Nwosu", role: "Threat Intel Lead", line: "An invitation just arrived. Tell me what it actually is." },
    "threat-intel-q5": { name: "Callista Nwosu", role: "Threat Intel Lead", line: "Leadership wants early warning. Where do you send them?" },
    "threat-intel-q2": { name: "Callista Nwosu", role: "Threat Intel Lead", line: "Two reports, and the platform wants a decision. Your call." },
    "threat-intel-q3": { name: "Callista Nwosu", role: "Threat Intel Lead", line: "It came with a label. Read the label before you touch it." },
    "threat-intel-la1": { name: "Callista Nwosu", role: "Threat Intel Lead", line: "Priority 1, on your screen. Walk me through it." },
    "threat-intel-flag1": { name: "Callista Nwosu", role: "Threat Intel Lead", line: "The detection engineers need a lookup key, not a name." },
  },
  briefings: {
    // ── Reading 1: from a question to a product ──
    "threat-intel-r1": [
      {
        kind: "rush",
        title: "Data or Intelligence?",
        prompt: "Callista opens the morning's inbox at Penrose Energy, with Ingrid Solheim's question on the wall: can the crew that hit Aldermoor Gas reach our substation engineers before the winter peak? Call each line: does it work as intelligence for someone here, or is it still data?",
        primer: {
          title: "What makes it intelligence",
          points: [
            "**CTI** (Cyber Threat Intelligence) means collecting information about attackers and turning it into guidance that helps defenders decide.",
            "**Data** is a raw fact: a blocked connection, a hash, a line in a feed.",
            "**Intelligence** is data that has been analysed and put in context, so that a person can make a decision.",
            "Three tests: did someone **ask**? Does it say **what it means**? Can a named person **act** on it?",
            "Being true isn't the test. A true fact nobody needs is still data.",
          ],
          example: {
            label: "The method, on a river",
            lines: [
              "A gauge reads 3.2 m. True, and nobody can act on it yet: data.",
              "The water board says the river is rising 10 cm an hour and tops the bank at 18:00, so move the pumps now.",
              "It says what the reading means and what to do, for someone who can do it: intelligence.",
            ],
          },
        },
        trueLabel: "Intelligence",
        falseLabel: "Data",
        seconds: 60,
        target: 10,
        cards: [
          { id: "c1", text: "48,000 new indicators from the overnight feed", answer: false, why: "Nobody asked for them, nobody has read them, and nothing says what they mean for Penrose." },
          { id: "c2", text: "Firewall denied 203.0.113.18 at 02:14", answer: false, why: "A true fact with no who, no why and no so-what." },
          { id: "c3", text: "Crew phishes utility engineers for VPN logins: check our 3 vendor accounts", answer: true, why: "It says what the crew does, why that touches Penrose, and what to do today." },
          { id: "c4", text: "Hash of a file seen somewhere on the internet", answer: false, why: "No context ties it to anyone here or to any decision." },
          { id: "c5", text: "Aldermoor fell through a vendor session. Ours use the same gateway type", answer: true, why: "Analysis has joined their incident to Penrose's setup, and Ingrid can act on that." },
          { id: "c6", text: "Top 10 malware families of the quarter, worldwide", answer: false, why: "Interesting and general. No decision at Penrose changes because of it." },
          { id: "c7", text: "This crew works weekends: add an analyst to the peak-week rota", answer: true, why: "A finding about behaviour turned into a decision the SOC manager can take." },
          { id: "c8", text: "Port 3389 scanned 1,200 times yesterday", answer: false, why: "Background noise until somebody says who, why and whether it matters." },
          { id: "c9", text: "The exploited gateway bug is on 2 of our 6 gateways: patch before Friday", answer: true, why: "Specific to Penrose, with an owner, an action and a date." },
          { id: "c10", text: "Domain registered today: grid-support.example", answer: false, why: "A fact. It becomes intelligence once analysis ties it to someone and says what to do." },
          { id: "c11", text: "That domain is now sending lures to our engineers: block it and warn them", answer: true, why: "The same fact, after analysis: it has a meaning and an action." },
          { id: "c12", text: "1.4 TB of logs ingested this week", answer: false, why: "A volume, not a finding." },
          { id: "c13", text: "A 40-page report on a crew that only targets banks", answer: false, why: "Well written, but for Penrose it answers a question nobody here asked. Somebody else's intelligence is your data." },
          { id: "c14", text: "Risk to utilities our size is rising, and the freeze plan still covers it", answer: true, why: "A judgement measured against a plan somebody owns. Intelligence doesn't have to be technical." },
        ],
        lesson: "Intelligence answers a question somebody asked. A true fact with no question behind it, no meaning and nobody to act on it is data, however fresh it is. Before you forward anything, name who needs it and what they will decide.",
      },
      {
        kind: "sequence",
        title: "Work One Question Round the Lifecycle",
        prompt: "Ingrid's question has reached Callista's desk. Tap what the team does next in the order it really happens, from the first conversation to what Ingrid says afterwards.",
        primer: {
          title: "The intelligence lifecycle",
          points: [
            "**Planning:** decide what question needs answering, and for whom. Everything after it spends effort on that question.",
            "**Collection** gathers from feeds, partners and open sources. **Processing** cleans, translates and de-duplicates it.",
            "**Analysis** works out what it means and what is likely next.",
            "**Dissemination** delivers it to the right people in a format they can use.",
            "**Feedback** is the people who used it telling the producers whether it helped. That sets the next round of Planning, so this is a cycle and not a line.",
          ],
          example: {
            label: "One round, at a retail chain",
            lines: [
              "Planning: stores ask if card skimmers are hitting shops like theirs.",
              "Collection: the retail peer group's reports. Processing: three spreadsheets merged, duplicates dropped.",
              "Analysis: one gang, two regions, one method. Dissemination: a single page for store managers.",
              "Feedback: useful, but send it before the weekend. The next round changes.",
            ],
          },
        },
        items: [
          { id: "analysis", text: "Compare what the crew did at Aldermoor with how Penrose's vendor sessions really work", note: "Analysis: this is the step that turns collected material into a judgement about Penrose." },
          { id: "planning", text: "Ingrid confirms the freeze decision needs an answer by 14 November and covers the 3 vendor support accounts", note: "Planning: the question, the deadline and the owner are agreed before anyone collects a thing." },
          { id: "feedback", text: "Ingrid says the page settled the freeze, and asks for the vendor names next time", note: "Feedback: the consumer tells the producer what worked. It changes the next requirement." },
          { id: "processing", text: "Put the three sources into one format and drop 31,000 rows of gateway health checks", note: "Processing: clean and de-duplicate first, or the analysts spend their week on noise." },
          { id: "dissemination", text: "Give Ingrid one page with a recommendation, and give detection engineers a technical annex", note: "Dissemination: the same findings in two formats, because each reader needs something different." },
          { id: "collection", text: "Pull peer reports, the vendor's report on Aldermoor and six months of remote access logs", note: "Collection: only what the question needs. The feed that was already running isn't a plan." },
        ],
        order: ["planning", "collection", "processing", "analysis", "dissemination", "feedback"],
        doneNote: "Planning comes first because every later step spends effort on the question it set. Feedback closes the loop, because what the consumer says sets the next round. Skip Planning and you get what many SOCs have: collection with no customer.",
      },
      {
        kind: "duel",
        title: "Which Product for Which Reader?",
        prompt: "By Wednesday Callista has five requests about the same crew. Play the product that answers each one. A played card is gone, and two of your cards answer nobody.",
        primer: {
          title: "One threat, four products",
          points: [
            "**Strategic:** the threat picture in plain language, for executives. No addresses, no hashes.",
            "**Operational:** one specific campaign: its aim, its targets, its timeframe. For SOC managers and incident responders preparing playbooks.",
            "**Tactical:** TTPs (Tactics, Techniques and Procedures), the attacker's methods step by step, usually mapped to MITRE ATT&CK. For the people writing detections.",
            "**Technical:** IOCs (Indicators of Compromise) such as IPs, domains and hashes. Machine-readable, and they age fast because attackers rotate them.",
            "Start from the reader and the decision, never from what you happen to have.",
          ],
          example: {
            label: "Same threat, an airline, three readers",
            lines: [
              "A firewall needs tonight's block list: **technical**.",
              "A detection engineer writes a rule for how the group steals tokens: **tactical**.",
              "An incident manager readies a playbook for this month's phishing wave: **operational**.",
            ],
          },
        },
        attacker: "The request queue",
        moves: [
          { id: "m1", move: "Head of Strategy: \"We may buy a stake in a grid operator abroad. Does that change who would want to hurt us?\"", detail: "The reader is deciding a deal, and has no security background.", counter: "strategic", hint: "Who is reading, and what do they own?", why: "A deal is a business decision, so it needs the threat in business language with no IPs or hashes. That's strategic intelligence, and its readers are executives." },
          { id: "m2", move: "SOC manager: \"Is the phishing wave against utilities still running? I want a playbook ready by Friday.\"", detail: "One operation, with a goal and targets, happening now.", counter: "operational", hint: "Is this about a group in general, or one live operation?", why: "A live campaign with a target set and a timeframe is operational intelligence. It tells SOC managers and responders what to prepare for." },
          { id: "m3", move: "Detection engineer: \"How does this crew get from a VPN session to the engineering network? I want a rule that outlasts their next server.\"", detail: "The question is about steps, not addresses.", counter: "tactical", hint: "What stays the same when the crew changes servers?", why: "Methods mapped to ATT&CK are tactical intelligence. Attackers replace servers in days and reuse methods across campaigns, so a rule on a technique lasts far longer than a blocklist." },
          { id: "m4", move: "Firewall engineer: \"Give me something I can load into the block policy before tonight's change window.\"", detail: "Machine-readable, needed today, and it will age fast.", counter: "technical", hint: "What can a firewall consume directly?", why: "IPs, domains and hashes are technical intelligence: the fastest thing to use and the fastest to go stale." },
          { id: "m5", move: "Regional manager: \"Just send me everything you have on cyber.\"", detail: "No question, no decision, no deadline.", counter: "ask", hint: "Which lifecycle phase is missing here?", why: "With no question there's nothing to answer. The right move is a short conversation that turns this into a requirement, which puts it back in Planning." },
        ],
        cards: [
          { id: "technical", name: "Indicator list", effect: "Domains, IPs and hashes in a machine-readable file." },
          { id: "rawfeed", name: "Forward the raw feed", effect: "48,000 indicators, unread." },
          { id: "strategic", name: "Strategic brief", effect: "Two pages of plain language. No technical detail." },
          { id: "ask", name: "Requirement conversation", effect: "Ten minutes: what are you deciding, and by when?" },
          { id: "tactical", name: "Technique profile", effect: "How the crew works, step by step, mapped to ATT&CK." },
          { id: "second", name: "Buy a second feed", effect: "More collection, and still no question." },
          { id: "operational", name: "Campaign advisory", effect: "One operation: aim, targets, timing." },
        ],
        lesson: "Start from the reader and their decision. Executives get strategic, campaign planners get operational, rule writers get tactical, machines get technical. A request with no decision behind it goes back to Planning, not to the feed.",
      },
    ],
    // ── Reading 2: who attacks, and who holds the answers ──
    "threat-intel-r2": [
      {
        kind: "lineup",
        title: "Sort Attackers by What They Want",
        prompt: "Before Callista collects anything, Penrose's own history gets a look. Four old incidents from the case system, four kinds of attacker. Read the evidence, open the dossiers, and name who fits.",
        primer: {
          title: "Read motive before tools",
          points: [
            "A threat actor is sorted by **what they want**, then by how much skill and patience they bring.",
            "**RaaS** (Ransomware-as-a-Service): one group supplies the malware and the infrastructure, and affiliates break in for a cut of the ransom.",
            "**APT** (Advanced Persistent Threat): a state-backed team. Persistent means it gets in quietly and stays.",
            "Median dwell time across all incidents is now days to weeks, but noisy ransomware pulls that figure down. A careful espionage crew can still sit unseen for months.",
          ],
          example: {
            label: "The method, at a shipping line",
            lines: [
              "A booking site goes offline for a day, with a slogan about a port dispute on the home page.",
              "No payment asked, nothing stolen: the point was to be seen.",
              "Motive first: a statement. That fits a hacktivist, whatever tool did it.",
            ],
          },
        },
        suspects: [
          { id: "crime", name: "Ransomware affiliate", motive: "Money: ransom, and stolen data for sale", skill: "Buys kits and access. Organised like a business", target: "Whoever can pay" },
          { id: "state", name: "State-backed APT", motive: "Espionage, sabotage, intellectual property", skill: "Custom malware, large teams, years of patience", target: "Critical infrastructure, defence, government" },
          { id: "kiddie", name: "Script kiddie", motive: "Curiosity and bragging", skill: "Runs other people's tools, often without understanding them", target: "Anything that answers a scan" },
          { id: "hack", name: "Hacktivist collective", motive: "Ideology: be seen, make a point", skill: "DDoS, defacement, data dumps", target: "Organisations they oppose" },
        ],
        rounds: [
          { id: "r1", evidence: ["Customer portal flooded for 40 minutes", "A channel posts a slogan against Penrose's new pipeline", "No ransom demand, no data taken"], suspect: "hack", why: "Being seen was the whole aim, and the protest gives the motive. DDoS and a public claim are the hacktivist pattern." },
          { id: "r2", evidence: ["Billing servers encrypted on a Friday night", "A note offers a decryptor, with a leak-site countdown", "The same kit hit a dairy and a law firm last month"], suspect: "crime", why: "Payment is the goal, and unrelated victims show targets chosen by who can pay. One kit across many victims fits RaaS, where many affiliates share a toolset." },
          { id: "r3", evidence: ["One public exploit fired at every address in Penrose's range", "The tool's default banner is left in every request", "It stops at the first error"], suspect: "kiddie", why: "Opportunistic, unmodified and easily stopped. Somebody ran a tool and hit whatever answered." },
          { id: "r4", evidence: ["A quiet account on an engineering file share for seven months", "It reads substation protection drawings and sells nothing", "An implant no vendor has seen before"], suspect: "state", why: "Seven months of patience, custom tooling and interest in how the grid works, with no money in it. That's the state-backed pattern: espionage, possibly preparing for sabotage." },
        ],
      },
      {
        kind: "duel",
        title: "Ask the Source That Can Answer",
        prompt: "The requirement is signed. Now Callista lists what Penrose doesn't know yet. Play the source built to fill each gap. A wrong source gives you plenty of true facts about something else, and two of your cards can't fill any of these gaps.",
        primer: {
          title: "Where the answers live",
          points: [
            "An **ISAC** (Information Sharing and Analysis Center) is a sector's own group: FS-ISAC for finance, H-ISAC for healthcare, E-ISAC for energy. Members share what hit them, under agreed rules.",
            "**CISA KEV** (Known Exploited Vulnerabilities) lists CVEs, the public IDs for software flaws, that are actively exploited in the wild. It covers bugs, not actors.",
            "**Abuse.ch** tracks malware infrastructure: URLhaus for bad URLs, MalwareBazaar for samples, Feodo Tracker for banking trojan C2 (command-and-control) servers. **AlienVault OTX** is community-contributed: fast and open, with confidence that varies.",
            "**Commercial services** such as Recorded Future, Mandiant Advantage and CrowdStrike Intelligence sell curated actor tracking and dark-web monitoring.",
            "**MISP** (Malware Information Sharing Platform) is open-source software that trusted partners run to swap structured reports, both ways.",
          ],
          example: {
            label: "Same trojan, a bank, two questions",
            lines: [
              "\"What are other banks seeing from it?\" Peers, under sharing rules: FS-ISAC.",
              "\"Which C2 servers is it using today?\" Infrastructure: Feodo Tracker.",
              "One topic, two questions, two sources. The question picks the source.",
            ],
          },
        },
        attacker: "The gap list",
        moves: [
          { id: "g1", move: "What did other utilities see from this crew, and what did they do about it?", detail: "You want peers' experience, shared under rules everyone agreed to.", counter: "isac", hint: "Who else runs a grid?", why: "E-ISAC exists for exactly this: energy companies telling each other what hit them. That first-hand detail rarely reaches an open feed." },
          { id: "g2", move: "Is the bug in our remote access gateway being used in real attacks?", detail: "One CVE number and a patch window to defend.", counter: "kev", hint: "Which list is about exploited flaws, not groups?", why: "If the CVE is on CISA KEV, it's being exploited in the wild and the patch moves up. The list won't say who is exploiting it." },
          { id: "g3", move: "Can the sandbox team get a copy of the loader from the Aldermoor report?", detail: "You have a hash. You want the file.", counter: "abuse", hint: "Which project collects malware files?", why: "Abuse.ch runs MalwareBazaar for samples, alongside URLhaus for malicious URLs." },
          { id: "g4", move: "Is anyone selling access to Penrose on criminal forums?", detail: "Nobody on the team has time to watch those forums.", counter: "commercial", hint: "Which card is somebody else's analysts, for a fee?", why: "Dark-web monitoring and curated actor tracking is what paid services sell." },
          { id: "g5", move: "Three neighbouring utilities want to swap structured reports on this crew, both ways.", detail: "Members write as well as read, and it's between trusted partners.", counter: "misp", hint: "Which one do partners run and write to themselves?", why: "MISP is free, open-source software, so partners can run an instance and each add reports." },
        ],
        cards: [
          { id: "taxii", name: "A TAXII server", effect: "Moves intelligence between platforms. Holds no answer of its own." },
          { id: "kev", name: "CISA KEV", effect: "CVEs known to be exploited." },
          { id: "isac", name: "E-ISAC", effect: "Energy sector members sharing with each other." },
          { id: "abuse", name: "Abuse.ch", effect: "Malware URLs, samples and C2 trackers." },
          { id: "otx", name: "AlienVault OTX", effect: "Community pulses: open, quick, confidence varies." },
          { id: "misp", name: "MISP community", effect: "Partners exchanging structured reports." },
          { id: "commercial", name: "Commercial intel service", effect: "Paid analysts and dark-web monitoring." },
        ],
        lesson: "Name the gap first, then the source built for it. Peers' experience comes from the sector's ISAC, exploited CVEs from KEV, malware samples and infrastructure from Abuse.ch, curated tracking from paid services, and two-way exchange from MISP. A source that can't answer the gap is noise, however good it is.",
      },
      {
        kind: "anatomy",
        title: "Anatomy of a MISP Event",
        prompt: "The utilities' exchange just sent its first entry to Penrose. Read it field by field the way Callista would, because each field decides what the team can do with it.",
        source: "MISP · event JSON · utilities exchange",
        fields: [
          { key: "Event.info", value: "Slate Heron lures to utility engineers, week 45", label: "Title", note: "An event is one report about an incident or campaign. Everything below hangs off it." },
          { key: "Event.Orgc.name", value: "Harrowfield Water", label: "Who wrote it", note: "Orgc is the organisation that created the event. Members write as well as read." },
          { key: "Event.threat_level_id", value: "2", label: "Threat level", note: "1 High, 2 Medium, 3 Low, 4 Undefined. It's the creator's opinion, so read it as one." },
          { key: "Event.analysis", value: "1", label: "Maturity", note: "0 Initial, 1 Ongoing, 2 Completed. Ongoing means this may change: check back before you build on it." },
          { key: "Event.distribution", value: "1", label: "Software reach", note: "0 Your organisation only, 1 This community only, 2 Connected communities, 3 All communities, 4 Sharing group. It controls how far MISP itself syncs the event." },
          { key: "Event.Tag[0].name", value: "tlp:green", label: "Human reach", note: "A TLP (Traffic Light Protocol) tag tells people how far they may pass it on. The release station covers it. Distribution binds the software, this binds you." },
          { key: "Attribute[0].type", value: "domain", label: "Indicator type", note: "An attribute is one individual IOC inside the event, with its own type and category." },
          { key: "Attribute[0].value", value: "gridcare-support.example" },
          { key: "Attribute[0].to_ids", value: "true", label: "Fit to detect on", note: "True means the creator thinks it's safe for automated detection. False means context only: export it to a SIEM and you get noise." },
          { key: "Attribute[1].type", value: "email-subject" },
          { key: "Attribute[1].to_ids", value: "false", note: "A subject line helps a human recognise the lure, but as a detection it would match too much." },
        ],
        summary: "MISP is open-source software: partners run it, read it and write to it, and many CERTs and ISACs use it. An event holds the story and attributes hold the individual IOCs, each with its own to_ids flag. Two separate controls set the reach: distribution for the software, TLP for people.",
      },
      {
        kind: "inspect",
        title: "What the Message Says and What Carries It",
        prompt: "Penrose's platform just pulled new items from the exchange's server. Tap each glowing line of the capture and read what it does: one layer moves the message, another one is the message, and one line is neither.",
        artifact: "Client request and server response · threat intel sync",
        items: [
          { id: "t1", text: "GET /api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/ HTTP/1.1", tag: "TAXII: transport", tone: "info", note: "TAXII (Trusted Automated eXchange of Intelligence Information) is the protocol. It defines servers, collections and how a client asks for them, the way HTTP defines how a browser gets a page." },
          { id: "t2", text: "Accept: application/taxii+json;version=2.1", tag: "TAXII: transport", tone: "info", note: "The client says which TAXII version it speaks. Nothing here describes a threat yet." },
          { id: "t3", text: "{ \"more\": false, \"objects\": [ ... ] }", tag: "TAXII: transport", tone: "info", note: "The envelope: it says whether more pages follow. The intelligence is inside objects." },
          { id: "s1", text: "\"type\": \"threat-actor\", \"name\": \"Slate Heron\"", tag: "STIX: content", tone: "trust", note: "STIX (Structured Threat Information Expression) is a JSON-based language for describing actors, campaigns, TTPs and IOCs. It doesn't care how it travels." },
          { id: "s2", text: "\"type\": \"indicator\", \"pattern\": \"[domain-name:value = 'gridcare-support.example']\", \"pattern_type\": \"stix\"", tag: "STIX: content", tone: "trust", note: "A machine can load this straight into a watchlist, which is how an indicator seen at one company reaches another in minutes." },
          { id: "s3", text: "\"type\": \"relationship\", \"relationship_type\": \"indicates\"", tag: "STIX: content", tone: "trust", note: "STIX can say how objects connect: this indicator points to that actor. A flat list of IOCs can't." },
          { id: "m1", text: "\"object_marking_refs\": [\"marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da\"]", tag: "A label, carried along", tone: "warn", note: "That reference is the TLP:GREEN marking. STIX carries the label." },
        ],
      },
    ],
    // ── q2: names, then the Diamond ──
    "threat-intel-q2": [
      {
        kind: "codebreak",
        title: "Decode the Vendor Names",
        prompt: "The Aldermoor reports are in, and no two of them speak the same language. Before Callista can file anything, crack the naming codes they rely on. Green is the right place, amber is in the word.",
        primer: {
          title: "How vendors name the same crews",
          points: [
            "**CrowdStrike** uses an animal for the country: BEAR Russia, PANDA China, KITTEN Iran, CHOLLIMA North Korea.",
            "**Mandiant** uses a prefix: APT plus a number for state-backed groups, FIN for financially motivated ones, UNC for clusters not yet categorised.",
            "**Microsoft** uses weather: Blizzard Russia, Typhoon China, Sandstorm Iran.",
            "**MITRE ATT&CK** gives every group an ID: G followed by four digits. Tooling looks groups up by that ID.",
            "A shared animal gives a country, **not a group**. Two Pandas can be two different crews.",
          ],
          example: {
            label: "One crew, four labels",
            lines: [
              "CrowdStrike: Charming Kitten. Mandiant: APT35. Microsoft: Mint Sandstorm.",
              "MITRE ATT&CK: Magic Hound, ID G0059.",
              "Four names, one group, and only the ID is built for a lookup.",
            ],
          },
        },
        rounds: [
          { id: "animal", clue: "A vendor writes Wicked Panda. Type the country that the animal stands for.", answer: "CHINA", why: "PANDA means China in CrowdStrike's scheme. The animal gives the country and nothing more." },
          { id: "unc", clue: "Mandiant's three-letter prefix for a cluster it hasn't categorised yet.", answer: "UNC", why: "UNC marks an uncategorised cluster. It can later be merged into an APT or FIN group, so expect names to move." },
          { id: "fin", clue: "A report blames a FIN group. In one word, what is that group after?", answer: "MONEY", why: "FIN groups are financially motivated, like FIN7 and FIN11." },
          { id: "weather", clue: "Microsoft's weather word for actors based in China.", answer: "TYPHOON", why: "Volt Typhoon and Brass Typhoon share the word, and they're two different groups. Blizzard is Russia, Sandstorm is Iran." },
        ],
        lesson: "A vendor's name tells you who wrote the report and, at most, a country. It doesn't prove that two reports describe one group, or two. Before you merge or split anything, check a crosswalk.",
      },
      {
        kind: "worksheet",
        title: "Check the Crosswalk Before You Merge",
        prompt: "Callista keeps a crosswalk: one row per group, one column per naming scheme. Use it the way you would before touching an actor profile: find the row, read across, then answer.",
        caption: "Threat intel platform · actor crosswalk · ATT&CK Groups and vendor reporting",
        columns: ["ATT&CK group", "ATT&CK ID", "CrowdStrike", "Mandiant", "Microsoft", "Sponsor or motive"],
        rows: [
          ["APT28", "G0007", "Fancy Bear", "APT28", "Forest Blizzard", "Russia, GRU"],
          ["APT29", "G0016", "Cozy Bear", "APT29", "Midnight Blizzard", "Russia, SVR"],
          ["Sandworm Team", "G0034", "Voodoo Bear", "APT44", "Seashell Blizzard", "Russia, GRU"],
          ["APT41", "G0096", "Wicked Panda", "APT41", "Brass Typhoon", "China, espionage and crime"],
          ["Volt Typhoon", "G1017", "Vanguard Panda", "UNC3236", "Volt Typhoon", "China, state-backed"],
          ["FIN7", "G0046", "Carbon Spider", "FIN7", "Sangria Tempest", "Criminal, financial"],
        ],
        questions: [
          { id: "lookup", q: "A detection engineer wants Voodoo Bear's technique profile, and the tooling looks groups up by ID. What goes in the lookup?", hint: "Find the name in the CrowdStrike column, then read across to the ID.", answer: ["G0034"], why: "Voodoo Bear is the Sandworm Team row, so G0034. A report's name gets you to the row, and the row gets you the key a tool can use." },
          { id: "merge", q: "One report says Voodoo Bear, another says APT44. One actor profile or two? (one/two)", hint: "Are both names on the same row?", answer: ["one", "1"], why: "Same row, different vendors. Two profiles would split one group's history in half." },
          { id: "split", q: "One report says Wicked Panda, another says Vanguard Panda. One actor profile or two? (one/two)", hint: "Same animal. Same row?", answer: ["two", "2"], why: "Both are Pandas, so both are China, but they sit on different rows. Merging on a shared animal would blend two crews' techniques into one false picture." },
        ],
      },
      {
        kind: "sort",
        title: "Fill the Diamond",
        prompt: "A vendor report on the Aldermoor intrusion and a pile of raw notes sit on Callista's desk. Build one event from them: who did this, with what, over what, to whom. Anything that doesn't fill a corner of this event goes in the fifth bin, however true it is.",
        primer: {
          title: "The Diamond Model",
          points: [
            "The **Diamond Model** of Intrusion Analysis describes one **event**, one thing an attacker did, with four corners. A second action gets its own Diamond.",
            "**Adversary:** who did it. **Victim:** who or what was hit, down to the team or the system.",
            "**Capability:** what they used against the victim: malware, an exploit, a tool.",
            "**Infrastructure:** what carried it there and talks back: domains, servers, sending accounts. Capability does the work. Infrastructure delivers it.",
            "A note that fills no corner stays out, however true. An empty corner is a finding: it's the next thing to collect.",
          ],
          example: {
            label: "One event, at a hotel chain",
            lines: [
              "Note: a booking agent opened a fake invoice from billing-hotels.example, a password stealer ran, and nobody knows who was behind it.",
              "Capability: the stealer. Infrastructure: billing-hotels.example. Victim: the agent's desktop, at the hotel chain.",
              "Adversary: unknown, so that corner stays empty and goes on the collection list.",
            ],
          },
        },
        buckets: [
          { id: "adversary", label: "Adversary" },
          { id: "capability", label: "Capability" },
          { id: "infrastructure", label: "Infrastructure" },
          { id: "victim", label: "Victim" },
          { id: "out", label: "Not this event" },
        ],
        items: [
          { id: "n1", text: "Vendor report, p.3: command-and-control domain vpn-support-portal.example", bucket: "infrastructure", why: "A domain the crew controls to talk to its implant. It carries the attack, so it can be blocked or taken down." },
          { id: "n2", text: "Feed: 48,000 new indicators, none seen at Aldermoor", bucket: "out", why: "Nothing ties them to this event. Volume isn't evidence." },
          { id: "n3", text: "Vendor report, p.1: activity tracked as Slate Heron, moderate confidence", bucket: "adversary", why: "Who did it, with how sure the writer is. Keep the confidence: a corner can be filled and still be soft." },
          { id: "n4", text: "Aldermoor ticket: ALD-ENG-WS14, a substation engineer's workstation", bucket: "victim", why: "The victim corner goes down to the system. This detail is what makes the event comparable with Penrose." },
          { id: "n5", text: "Vendor report, p.3: HollowPike, a loader that runs from memory", bucket: "capability", why: "Malware is the textbook capability: it does the work on the victim's machine." },
          { id: "n6", text: "Firewall note: rented server at 203.0.113.71 receiving the HTTPS beacons", bucket: "infrastructure", why: "A server the crew rents to receive traffic. It's a place, not a tool." },
          { id: "n7", text: "Vendor report, p.7: this crew's 2023 attack on a shipping firm", bucket: "out", why: "A different event, which gets its own Diamond. Linking the two later is analysis. Packing them into one blurs all four corners." },
          { id: "n8", text: "Vendor report, p.4: a public exploit for the remote access gateway's login page", bucket: "capability", why: "An exploit is something the crew uses against the victim, so it's capability. The gateway it hits is on the victim's side." },
          { id: "n9", text: "ISAC note: Aldermoor's responders track the same crew as TA-771", bucket: "adversary", why: "A second name for the same corner, and exactly what a crosswalk is for. One crew, not two adversaries." },
          { id: "n10", text: "Aldermoor ticket: Aldermoor Gas, a regional gas distributor", bucket: "victim", why: "The organisation in the victim corner. Its sector and size show who else looks like this." },
          { id: "n11", text: "Firewall note: scan from 198.51.100.12, blocked the day before, source unrelated", bucket: "out", why: "True, recent and on the same firewall, with nothing linking it to the crew. Timing alone doesn't put a note in the event." },
          { id: "n12", text: "Vendor report, p.5: lures sent from a free webmail account, it.vendor.desk@mail.example", bucket: "infrastructure", why: "The sending account is the route to the victim, which makes it infrastructure." },
          { id: "n13", text: "Vendor report, p.9: worldwide ransomware payments fell 4% last year", bucket: "out", why: "A market statistic. It may suit a strategic brief, but it isn't part of what happened at Aldermoor." },
          { id: "n14", text: "Aldermoor ticket: a script that dumped saved RDP credentials, left in a temp folder", bucket: "capability", why: "A tool the crew ran on the victim's system. It's a capability even though it's only a script." },
        ],
      },
      {
        kind: "worksheet",
        title: "Does the Diamond Answer Ingrid?",
        prompt: "The event is filled, but nobody asked for a diamond. Ingrid asked whether this crew can reach Penrose's engineers, and whether to freeze vendor sessions. Lay the Aldermoor corners beside Penrose's own facts, then answer what was asked.",
        caption: "Aldermoor event beside Penrose · working paper",
        columns: ["Corner", "Aldermoor event", "What Penrose has"],
        rows: [
          ["Adversary", "Slate Heron, moderate confidence, one vendor's assessment", "Nothing of Penrose's own on this crew"],
          ["Capability", "Gateway login exploit, HollowPike loader", "2 of 6 gateways run the vulnerable build"],
          ["Infrastructure", "vpn-support-portal.example, 203.0.113.71", "0 connections in six months of logs"],
          ["Victim", "Regional distributor, a substation engineer's workstation", "Regional distributor, 3 vendor accounts reach 41 engineer workstations"],
        ],
        questions: [
          { id: "gateways", q: "On how many Penrose gateways could the same exploit work today?", hint: "Read the capability row.", answer: ["2", "two"], why: "Two of six. That's the one finding that turns a story about Aldermoor into a fact about Penrose." },
          { id: "clear", q: "Infrastructure shows 0 connections in six months. Does that put Penrose in the clear? (yes/no)", hint: "How long does a crew keep one server?", answer: ["no"], why: "Attackers swap servers in days. Zero hits says those addresses weren't used here. It doesn't say the crew can't come, because capability and victim still fit." },
          { id: "freeze", q: "Should Ingrid restrict the vendor sessions until those gateways are patched? (yes/no)", hint: "Same kind of victim, same way in, and a date that can't move.", answer: ["yes"], why: "That's the answer to the question asked: a recommendation, with its confidence stated, on a decision Ingrid owns. A week of feed could never have given it." },
          { id: "next", q: "Which corner is thinnest, and so sets the next collection requirement?", hint: "Which row rests on one outsider's opinion?", answer: ["adversary", "the adversary"], why: "One vendor at moderate confidence, and nothing of Penrose's own. A weak corner isn't a failure, and it tells the next round of Planning where to look." },
        ],
      },
    ],
    // ── Reading 3: release it, then use it ──
    "threat-intel-r3": [
      {
        kind: "rush",
        title: "Send or Hold?",
        prompt: "Callista's assessment and the sources behind it are leaving the team. Penrose also runs monitoring for two small municipal utilities, and those are its clients. Each card is one item, its label, and where somebody wants to send it. Call it before the button gets pressed.",
        primer: {
          title: "TLP 2.0: how far it may travel",
          points: [
            "**TLP** (Traffic Light Protocol, from FIRST.org) tells a reader how far they may pass something on. The current standard is TLP 2.0.",
            "**RED:** the named recipients only. **AMBER+STRICT:** your organisation only.",
            "**AMBER:** your organisation and the clients who need it.",
            "**GREEN:** your wider community and peers, never a public channel. **CLEAR:** anyone, including the public.",
            "**TLP:WHITE** is the pre-2022 name for CLEAR, so treat it as CLEAR. TLP is about sharing only. It says nothing about age, accuracy or severity.",
          ],
          example: {
            label: "The method, at a law firm",
            lines: [
              "A TLP:GREEN note names a phishing kit. Warn a security group of other law firms? Peers in the community: yes.",
              "Post it on the firm's blog? A public channel: no.",
              "Find the furthest the label allows, then ask whether this audience is inside it.",
            ],
          },
        },
        trueLabel: "Send",
        falseLabel: "Hold",
        seconds: 60,
        target: 10,
        cards: [
          { id: "t1", text: "TLP:CLEAR advisory. Post it on the public blog", answer: true, why: "CLEAR has no limit on disclosure." },
          { id: "t2", text: "TLP:GREEN note. Share in the E-ISAC members' channel", answer: true, why: "GREEN reaches peers in the community, and a members' channel isn't public." },
          { id: "t3", text: "TLP:GREEN note. Quote it in a press release", answer: false, why: "GREEN stops short of public channels. A press release is as public as it gets." },
          { id: "t4", text: "TLP:RED brief. Forward it to the whole SOC", answer: false, why: "RED means named recipients only, not even the rest of your own team." },
          { id: "t5", text: "TLP:RED brief. Discuss it with the two people named on it", answer: true, why: "Named recipients are exactly who RED allows." },
          { id: "t6", text: "TLP:AMBER+STRICT report. Send it to a municipal client", answer: false, why: "STRICT stops at your own organisation. That extra word exists to rule out clients." },
          { id: "t7", text: "TLP:AMBER+STRICT report. Brief Penrose's detection team", answer: true, why: "Inside the organisation is where STRICT allows it." },
          { id: "t8", text: "TLP:AMBER+STRICT report. Share it with a peer utility", answer: false, why: "Peers are further out than clients, and STRICT doesn't reach even clients." },
          { id: "t9", text: "TLP:WHITE file from an old feed. Publish the indicators", answer: true, why: "WHITE is the retired name for CLEAR. Treat it as CLEAR, and notice that the sender's tooling is out of date." },
          { id: "t10", text: "TLP:GREEN note. Put it on the staff intranet", answer: true, why: "Your own organisation sits inside the community, and an intranet isn't public." },
          { id: "t11", text: "Partner email with no label. Forward it to the ISAC", answer: false, why: "No label doesn't mean no limit. Ask the sender before it moves." },
          { id: "t12", text: "TLP:RED brief. Paraphrase it on the ISAC call", answer: false, why: "Rewording still discloses it. The restriction covers the information, not just the document." },
          { id: "t13", text: "TLP:CLEAR advisory. Send it to all clients", answer: true, why: "Anyone may have it." },
          { id: "t14", text: "TLP:GREEN note. Pass it to another utility's SOC", answer: true, why: "A peer in your community, which is who GREEN was written for." },
        ],
        lesson: "Find the furthest the label allows, then check whether this audience is inside it. STRICT stops at your own walls, plain AMBER goes one step further to clients who need it, and GREEN reaches peers but no public channel. With no label, ask the sender. Getting this wrong can tip off the very actor someone was tracking.",
      },
      {
        kind: "match",
        title: "What Does This Intelligence Change?",
        prompt: "The release went out. Now each piece of it has to change something on the SOC floor, or the week was wasted. Pair each piece with the work it feeds.",
        primer: {
          title: "Four ways intelligence reaches the SOC",
          points: [
            "**IOC matching:** indicators are loaded into the SIEM (Security Information and Event Management) and compared with logs in real time. Someone else already did the identifying.",
            "**Threat hunting:** take a TTP and go looking for it, before any alert fires.",
            "**Enrichment:** the SIEM or SOAR attaches what's known to an alert, so triage starts with context.",
            "**Detection engineering:** a reported technique becomes a lasting rule, the detect, learn, improve loop.",
            "Every indicator should carry a **confidence** rating: a government advisory outweighs one anonymous community post. TTPs last longer than IOCs, because attackers swap addresses in days and reuse methods.",
          ],
          example: {
            label: "The method, on a hospital's report",
            lines: [
              "\"Crew X schedules a task called Backup_Sync in a temp folder.\" That's behaviour, so hunt for it.",
              "\"It beacons to 198.51.100.61.\" That's one address, so load it as an IOC with an expiry date.",
              "One report, two uses, because the two lines age differently.",
            ],
          },
        },
        pairs: [
          { id: "p1", left: "Five fresh domains from the exchange, confidence medium or better", right: "Load them so the SIEM alerts on any hit", why: "IOC matching: the identifying is already done, so a match can raise an alert straight away." },
          { id: "p2", left: "The crew names its scheduled tasks GridSync and runs them from ProgramData", right: "Search for it now, though no alert has fired", why: "A hunt starts from behaviour. If it's already here, an existing rule may have missed it." },
          { id: "p3", left: "Actor, first-seen date, confidence and source for a domain in an open alert", right: "Attach it to the alert so triage starts informed", why: "Enrichment answers the analyst's first question, whether this is real, without leaving the alert." },
          { id: "p4", left: "New technique: the crew reads saved RDP credentials through a signed binary", right: "Build a lasting SIEM or EDR rule", why: "Detection engineering: next time this technique is used, the SOC catches it automatically." },
          { id: "p5", left: "One unverified community post about a single IP", right: "Keep it as context, and page nobody on it", why: "Low confidence from an unvetted source is a lead. Blocking or paging on it alone trades noise for very little." },
        ],
      },
    ],
    // ── la1: the first hit ──
    "threat-intel-la1": [
      {
        kind: "anatomy",
        title: "Read a Threat Intel Match Field by Field",
        prompt: "27 November, a cold snap, and the SIEM raises Penrose's worst match on the crew. Before anyone decides anything, read what the enrichment gives you, and what it doesn't.",
        source: "SIEM alert · threat intel match · PEN-JMP02",
        fields: [
          { key: "rule.name", value: "Utilities Exchange IOC Match", label: "What fired", note: "A match rule fires whenever a log line touches a listed value. It says the value appeared and nothing about what happened." },
          { key: "data.indicator", value: "gridcare-support.example" },
          { key: "data.indicator_type", value: "domain" },
          { key: "data.confidence", value: "medium", label: "How sure", note: "How sure the producer is about the indicator, not about this incident. Only your own records can settle the incident." },
          { key: "data.source", value: "Utilities exchange (MISP event 2291)", label: "Who vouches", note: "Weigh the source: a government advisory or a sector partner's first-hand report counts for more than one anonymous community post." },
          { key: "data.actor", value: "Slate Heron", label: "One vendor's name", note: "A name is a starting point. To pull a technique profile from ATT&CK, tooling needs the Group ID, so take the name to the crosswalk. Slate Heron is a new cluster with no ATT&CK entry yet." },
          { key: "data.campaign", value: "Winter Relay" },
          { key: "data.first_seen", value: "2026-11-03", label: "Age", note: "This field tells you how old the indicator is. Judge freshness here." },
          { key: "data.tlp", value: "GREEN", label: "Sharing rule", note: "TLP only says how far you may share this." },
          { key: "matched.hostname", value: "PEN-JMP02", label: "Where", note: "The only jump host into the substation network. The role of the host sets how much a true match would matter." },
          { key: "matched.srcip", value: "10.40.2.8", note: "The internal side of the flow. This is the host that opened the connection." },
        ],
        summary: "Enrichment tells you what the outside world knows about an indicator. It can't tell you what happened here: whether the connection worked, how often, or what moved. The fields that feel like a verdict are about the indicator, so the verdict has to come from your own logs.",
      },
      {
        kind: "queue",
        title: "Prove the Match With Your Own Logs",
        prompt: "Four matches are in the queue, and the firewall records are already pulled for each one. Open each alert, read the session evidence beside the enrichment, and take the action Callista would.",
        primer: {
          title: "A match is a lead, not a verdict",
          points: [
            "An IOC hit says a host touched something on a list. It doesn't say the connection worked, or what it did.",
            "Ask your own session records three things: was it **allowed or blocked**? Does it **repeat on a rhythm**? Which way did the **bytes** go?",
            "Allowed, regular and more out than in looks like a beacon sending data home. One denied attempt means something tried and failed.",
            "Only your own logs can show what happened on your network.",
            "Check the innocent explanation against the host's real behaviour, and weigh the host: the same pattern on a lobby kiosk and on a server everyone depends on are different incidents.",
          ],
          example: {
            label: "The method, at a school district",
            lines: [
              "IOC hit: a library PC to a listed address.",
              "Firewall: denied, once, at 11:02, 0 bytes.",
              "No live channel exists, so no containment yet. Someone should still find out what made that request.",
            ],
          },
        },
        console: "SIEM · Threat intel matches",
        actions: [
          { id: "close", label: "Close with a note", tone: "close" },
          { id: "tier2", label: "Send to Tier 2 to check the host", tone: "escalate" },
          { id: "contain", label: "Contain and call IR", tone: "contain" },
        ],
        alerts: [
          {
            id: "kiosk", time: "02:41", severity: "High", rule: "Utilities Exchange IOC Match", entity: "PEN-KIOSK03",
            fields: [{ k: "data.indicator", v: "gridcare-support.example" }, { k: "data.confidence", v: "medium" }, { k: "firewall action", v: "deny" }, { k: "sessions", v: "1" }, { k: "bytes out / in", v: "0 / 0" }],
            context: "A visitor kiosk in the head office lobby. It has one attempt, denied, and nothing since.",
            answer: "tier2", why: "Nothing got through, so nothing needs containing. But a kiosk has no reason to look up that domain, so someone should find out what asked for it. Closing would throw that lead away.",
          },
          {
            id: "jmp", time: "03:02", severity: "Critical", rule: "Utilities Exchange IOC Match", entity: "PEN-JMP02",
            fields: [{ k: "data.indicator", v: "gridcare-support.example" }, { k: "data.confidence", v: "medium" }, { k: "firewall action", v: "allow" }, { k: "sessions", v: "10, every 15 minutes since 00:45" }, { k: "bytes out / in", v: "940 MB / 6 MB" }],
            context: "The only jump host into the substation network. The duty engineer suggests it's the backup vendor's nightly job, which writes once, at 01:00, to the internal backup server.",
            answer: "contain", why: "Medium confidence is enough, because your own firewall has confirmed the rest: allowed, regular, and far more out than in, on the most sensitive host you run. A single nightly write to an internal server doesn't explain a listed domain every 15 minutes.",
          },
          {
            id: "sbx", time: "03:10", severity: "High", rule: "Utilities Exchange IOC Match", entity: "PEN-CTI-SBX01",
            fields: [{ k: "data.indicator", v: "gridcare-support.example" }, { k: "data.confidence", v: "medium" }, { k: "firewall action", v: "allow" }, { k: "sessions", v: "3" }, { k: "bytes out / in", v: "4 KB / 19 KB" }, { k: "change ticket", v: "CTI-418" }],
            context: "The threat intel team's sandbox, on its own isolated VLAN. Ticket CTI-418 records a sample being detonated at 03:08 by the on-call analyst.",
            answer: "close", why: "A real hit with an honest cause: the team's own detonation, on a sandbox, with a ticket that matches the time. Note the ticket number and close it. Don't exclude the indicator from the rule, or the next real hit goes quiet.",
          },
          {
            id: "cdn", time: "03:15", severity: "Medium", rule: "Community Feed IOC Match", entity: "PEN-HR-LT22",
            fields: [{ k: "data.indicator", v: "198.51.100.200" }, { k: "data.confidence", v: "low" }, { k: "data.source", v: "One community pulse, 2 years old" }, { k: "firewall action", v: "allow" }, { k: "sessions", v: "1" }, { k: "bytes out / in", v: "2 KB / 14 KB" }],
            context: "The address now belongs to a content delivery network serving thousands of unrelated sites. A browser fetched one small file and never returned.",
            answer: "close", why: "Low confidence, old, a shared address, and your logs show one small download with no rhythm. Nothing here points to a live channel. Note why, and flag the indicator for review.",
          },
        ],
      },
      {
        kind: "sequence",
        title: "Contain a Host People Depend On",
        prompt: "PEN-JMP02 is confirmed, and 14 engineers are working through it during a cold snap. Isolating it outright would lock them out of the substations. Tap the first hour in the order Callista would run it.",
        primer: {
          title: "The order of a live incident",
          points: [
            "A confirmed, live channel is an incident, so **IR** (incident response) joins now and runs the work from here.",
            "**Owner:** whoever runs the host knows what would break. They are on the call before anything changes.",
            "**Cut:** stop the channel in a way the service can survive. That can be full isolation, or a firewall rule on the C2 path when isolation would stop the work.",
            "**Scope:** work out what the actor touched and what they hold.",
            "**Clean:** remove what scoping found. Each step depends on the one before it.",
          ],
          example: {
            label: "The method, on a payroll server",
            lines: [
              "A confirmed beacon, two days before pay run, and isolating would stop the pay file.",
              "Call the payroll owner and IR. A firewall rule cuts the C2 range, and the server keeps its link to the bank.",
              "Capture memory while it's contained, scope what it touched, then rotate the service account.",
            ],
          },
        },
        items: [
          { id: "scope", text: "Capture memory, and scope which accounts and substations that session touched", note: "Scoping tells you what to clean. With the channel cut, this can take the time it needs." },
          { id: "bridge", text: "Get the grid operations duty lead and the IR team on one call", note: "The owner knows what would break, and IR now runs this. Neither can be told afterwards." },
          { id: "rotate", text: "Rotate the vendor account's credentials and rebuild the host", note: "Eradication comes last, when you know everything the actor holds." },
          { id: "cut", text: "Add an egress rule cutting the host's path to the C2 domain and its range, keeping the engineers' sessions up", note: "The channel dies and the grid keeps its access. It's less clean than isolating, and it's the right call on a host people depend on." },
        ],
        order: ["bridge", "cut", "scope", "rotate"],
        doneNote: "Stop the bleeding with the owner beside you, then scope, then clean.",
      },
    ],
  },
};
