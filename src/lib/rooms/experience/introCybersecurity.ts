import type { RoomExperience } from "./types";

// "Operation First Look" for the "intro-cybersecurity" room (rooms-batch-01.ts),
// the first room every learner meets. Script: docs/campaign/01-intro-cybersecurity-v2.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// The story is the learning itself: a first day at the SOC academy in the
// fictional city of Northport, seen through a "Cyber Lens". Each station
// teaches one reading's topics through games and switches on one lens layer.
// Lab examples are deliberately different from the graded tasks: no flooded
// records system (q1), no poisoned software update (q2), no bank email (q3),
// a USB worm whose removal failed rather than a quarantined web download (la1),
// and the career wall leaves out the entry-level role (q4).
export const INTRO_CYBERSECURITY: RoomExperience = {
  roomId: "intro-cybersecurity",
  codename: "Operation First Look",
  theme: "city",
  handler: { name: "Maya Cohen", role: "Senior Analyst, Northport SOC Academy" },
  briefing: [
    "Day one. Northport SOC Academy.",
    "Maya Cohen hands you a pair of glasses: the Cyber Lens.",
    "Through it you see what nobody else sees: the connections, the data, and the people trying to steal it.",
    "Today nobody fights anybody. Today you learn to see.",
  ],
  mission: "Put on the Cyber Lens and switch on its five layers: what we defend, the three things that keep it safe, who attacks and how, what an alert looks like, and where your career starts.",
  estimate: "~40 min",
  look: { primary: "#2dd4bf", secondary: "#60a5fa", warn: "#f43f5e" },
  scene: "city",
  layout: "lens",
  stations: [
    {
      id: "connections",
      label: "Connections",
      topic: "What cybersecurity is · the attack surface · a short history",
      tagline: "Everything around you is a computer, and every computer can be attacked",
      building: "control",
      taskIds: ["intro-cyber-r1"],
    },
    {
      id: "locks",
      label: "The Three Locks",
      topic: "The CIA triad: confidentiality, integrity, availability",
      tagline: "The three things every system needs to stay safe. Open each lock",
      building: "vault",
      taskIds: ["intro-cyber-r2", "intro-cyber-m1", "intro-cyber-q1"],
    },
    {
      id: "attackers",
      label: "Attackers and Their Tricks",
      topic: "Threat actors · phishing, ransomware, DDoS, MitM, social engineering",
      tagline: "Meet the five kinds of attacker and the tricks they use",
      building: "archive",
      taskIds: ["intro-cyber-r2b", "intro-cyber-q2", "intro-cyber-q3"],
    },
    {
      id: "alert",
      label: "The Alert",
      topic: "Reading a security alert field by field",
      tagline: "Everything you learned, the way an analyst sees it: work your first alert",
      building: "ticket",
      taskIds: ["intro-cyber-la1"],
    },
    {
      id: "badge",
      label: "Badge Day",
      topic: "Real-world impact · cybersecurity careers",
      tagline: "Why this work matters, where a career starts, and your academy badge",
      building: "office",
      taskIds: ["intro-cyber-r3", "intro-cyber-q4"],
      boss: true,
    },
  ],
  personas: {
    "intro-cyber-q1": {
      name: "Dana Price",
      role: "Head of IT, Northport General Hospital",
      line: "You have seen the three locks. Here is what happened to one of our systems. Tell me which lock we lost.",
    },
    "intro-cyber-q2": {
      name: "Maya Cohen",
      role: "Senior Analyst",
      line: "A famous case from the archive. Read the file and tell me what kind of attacker we are looking at.",
    },
    "intro-cyber-q3": {
      name: "Maya Cohen",
      role: "Senior Analyst",
      line: "This one came in on the training feed. Name the attack the way you would in a ticket.",
    },
    "intro-cyber-q4": {
      name: "Daniel Brooks",
      role: "Director, Northport SOC Academy",
      line: "Good work today. Before I sign your badge: where does a career like yours usually start?",
    },
  },
  briefings: {
    // ── Reading 1: what cybersecurity is, the attack surface, a short history ──
    "intro-cyber-r1": [
      {
        kind: "xray",
        title: "X-Ray the City",
        prompt: "Cybersecurity protects computers, networks and data. But where are the computers? Scan the street with the lens: each everyday object hides one.",
        objects: [
          { id: "fridge", icon: "fridge", label: "Smart fridge", inside: "A small computer with Wi-Fi that orders groceries and talks to an app.", risk: "It becomes a foothold on the home network, or one of thousands of devices in a botnet." },
          { id: "traffic", icon: "traffic", label: "Traffic light", inside: "A controller on the city network that sets the timing of every junction.", risk: "Junctions jam, or worse, two directions get green at once." },
          { id: "atm", icon: "atm", label: "Cash machine", inside: "A computer running Windows, connected to the bank's network.", risk: "Card details are skimmed, or the machine is told to empty its cash." },
          { id: "pump", icon: "pump", label: "Insulin pump", inside: "A medical device with Bluetooth that receives dose settings.", risk: "A wrong dose: a cyberattack that can physically harm someone." },
          { id: "car", icon: "car", label: "Modern car", inside: "Dozens of small computers, a SIM card and over-the-air updates.", risk: "Doors unlocked remotely, or location tracked." },
          { id: "camera", icon: "camera", label: "CCTV camera", inside: "A network camera, often still on its factory-default password.", risk: "Strangers watch the feed, or switch the camera off." },
          { id: "phone", icon: "phone", label: "Your phone", inside: "A full computer that holds your email, bank app and passwords.", risk: "Every account you own is opened at once." },
          { id: "plant", icon: "plant", label: "Power plant", inside: "Industrial control computers that run turbines and the grid.", risk: "A blackout for the whole city." },
        ],
        doneNote: "Almost everything runs on computers, and almost every computer is connected. That is why cybersecurity matters: it protects money, privacy and even lives.",
      },
      {
        kind: "sort",
        title: "Attack Surface Sweep",
        prompt: "The attack surface is everything an attacker can target. Maya points at a city office: sort every entry point she names by what it is.",
        buckets: [
          { id: "device", label: "Device" },
          { id: "service", label: "App or network" },
          { id: "person", label: "Person" },
        ],
        items: [
          { id: "laptop", text: "A laptop a clerk takes home every night", bucket: "device", why: "Devices that leave the building are part of what you defend." },
          { id: "wifi", text: "The free guest Wi-Fi in the lobby", bucket: "service", why: "A network anyone can join is part of the attack surface." },
          { id: "portal", text: "The city's online parking-permit website", bucket: "service", why: "An internet-facing application can be reached by anyone, day and night." },
          { id: "printer", text: "The networked printer in the corridor", bucket: "device", why: "Printers are computers too, and rarely updated." },
          { id: "inbox", text: "A receptionist reading her email", bucket: "person", why: "People are on the attack surface: one convincing email reaches them directly." },
          { id: "phone", text: "The help-desk worker answering calls", bucket: "person", why: "A caller pretending to be a manager is attacking a person, not a computer." },
        ],
      },
      {
        kind: "sequence",
        title: "Timeline Rush",
        prompt: "Four moments that shaped the field. Put them in the order they happened.",
        items: [
          { id: "colonial", text: "Ransomware shuts down the largest US fuel pipeline", note: "Colonial Pipeline, 2021: fuel shortages along the East Coast." },
          { id: "isolated", text: "Computers are rare, expensive and mostly unconnected", note: "1970s: little to attack, so security is barely a topic." },
          { id: "solarwinds", text: "A backdoor ships inside a trusted software update", note: "SolarWinds, 2020: about 18,000 organisations install it." },
          { id: "morris", text: "The first worm spreads across the young internet", note: "Morris Worm, 1988: about 6,000 machines, roughly 10% of the internet." },
        ],
        order: ["isolated", "morris", "solarwinds", "colonial"],
        doneNote: "From isolated machines to attacks that empty petrol stations. The more we connect, the bigger the attack surface, and that is why SOCs exist.",
      },
    ],
    // ── Reading 2: the CIA triad ──
    "intro-cyber-r2": [
      {
        kind: "locks",
        title: "Three Locks",
        prompt: "Every system you scanned needs three things to stay safe. Each door below holds one of them. Open all three.",
        locks: [
          {
            id: "c", letter: "C", name: "Confidentiality",
            idea: "Only the right people can see it.",
            example: "Like a sealed letter: only the person it is addressed to should read it. Medical records, salaries and passwords all need this lock.",
            check: { q: "Which of these breaks this lock?", options: ["A neighbour opens your post and reads your bank statement", "The postman delivers your letter a day late"], answer: 0, why: "Someone who should not see the data saw it. The late letter is a different lock." },
          },
          {
            id: "i", letter: "I", name: "Integrity",
            idea: "Nobody can secretly change it.",
            example: "Like a signed contract: if one number changes after signing, the whole contract is worthless. Doses, payments and records all need this lock.",
            check: { q: "Which of these breaks this lock?", options: ["Someone reads a copy of your contract", "Someone changes the delivery date in your contract after you sign it"], answer: 1, why: "The data was altered without permission, so it can no longer be trusted." },
          },
          {
            id: "a", letter: "A", name: "Availability",
            idea: "It works when you need it.",
            example: "Like a shop: it is only useful while its doors are open. A system nobody can reach is as bad as no system.",
            check: { q: "Which of these breaks this lock?", options: ["The school's exam-results website crashes on results day", "A stranger sees your exam results"], answer: 0, why: "Nobody could use the system at the moment they needed it." },
          },
        ],
      },
      {
        kind: "reactor",
        title: "Triad Reactor",
        prompt: "Now at speed. Incidents from around Northport roll in on the conveyor. Route each one to the lock it breaks before it reaches the end of the belt.",
        reactors: [
          { id: "c", label: "Confidentiality", sub: "Who can see it?" },
          { id: "i", label: "Integrity", sub: "Is it still true?" },
          { id: "a", label: "Availability", sub: "Can we use it now?" },
        ],
        items: [
          { id: "pupils", text: "Pupils' home addresses from the school system appear on a forum", reactor: "c", why: "Private data reached people who should never see it." },
          { id: "lights", text: "A traffic light's timing is changed so both directions get green", reactor: "i", why: "The system's settings were altered: it still runs, but it can no longer be trusted." },
          { id: "bus", text: "Ransomware locks the city's bus timetable system", reactor: "a", why: "Nobody can use the timetables when they need them." },
          { id: "atm", text: "Someone reads a customer's balance over their shoulder at the cash machine", reactor: "c", why: "An unauthorised person saw private information." },
          { id: "bill", text: "The amount on a water bill is quietly changed", reactor: "i", why: "A record was falsified, so the customer pays the wrong amount." },
          { id: "storm", text: "A storm knocks out the power plant's control network", reactor: "a", why: "Availability is not only about attackers: any outage counts." },
        ],
      },
    ],
    // ── Reading 2b: who attacks, and how ──
    "intro-cyber-r2b": [
      {
        kind: "lineup",
        title: "Suspect Line-up",
        prompt: "Five kinds of attacker behind the glass. Each round brings evidence: pick who fits.",
        suspects: [
          { id: "kiddie", name: "Script Kiddie", motive: "Thrills, bragging rights", skill: "Low: uses other people's tools", target: "Anything that is easy" },
          { id: "criminal", name: "Cybercriminal", motive: "Money", skill: "Organised, professional", target: "Whoever will pay" },
          { id: "hacktivist", name: "Hacktivist", motive: "A political or social cause", skill: "Varies", target: "Symbols of what they oppose" },
          { id: "nation", name: "Nation-State", motive: "Espionage, sabotage", skill: "Very high, patient", target: "Governments, strategic sectors" },
          { id: "insider", name: "Insider", motive: "Grudge, gain or a mistake", skill: "Already has access", target: "Their own organisation" },
        ],
        rounds: [
          { id: "r1", evidence: ["The city council website shows a protest banner", "A manifesto was posted on social media an hour later"], suspect: "hacktivist", why: "Defacement plus a public cause: the goal is attention for a message, not money." },
          { id: "r2", evidence: ["A free attack tool was downloaded from a forum", "It was run against hundreds of random sites", "The attacker bragged about it in a chat room"], suspect: "kiddie", why: "Borrowed tools, random targets and bragging: low skill, high noise." },
          { id: "r3", evidence: ["Files on a dental clinic's servers were encrypted", "A note demands payment in Bitcoin", "Stolen files are threatened on a leak site"], suspect: "criminal", why: "Encrypt, extort, threaten to leak: the business model of organised crime." },
          { id: "r4", evidence: ["A billing clerk resigned last Friday", "On Thursday, the customer list was copied to a USB stick from her account"], suspect: "insider", why: "Legitimate access used against the organisation, right before leaving." },
          { id: "r5", evidence: ["A defence ministry's email was read for 14 months", "Custom tools, no ransom, nothing destroyed"], suspect: "nation", why: "Long, quiet, well-funded and after secrets: the signature of state espionage." },
        ],
      },
      {
        kind: "tricks",
        title: "Trick Cards",
        prompt: "Every cyberattack is an old trick in new clothes. Flip each card, read the everyday trick, and stamp it with the attack that works the same way.",
        attacks: [
          { id: "phishing", name: "Phishing" },
          { id: "ransomware", name: "Ransomware" },
          { id: "ddos", name: "DDoS" },
          { id: "mitm", name: "Man-in-the-Middle" },
          { id: "social", name: "Social engineering" },
        ],
        cards: [
          { id: "pizza", analogy: "Hundreds of prank callers ring a pizza shop non-stop, so real customers cannot get through.", attack: "ddos", real: "DDoS (Distributed Denial of Service): thousands of machines flood a server with fake requests until real users cannot reach it." },
          { id: "landlord", analogy: "A letter that looks like it is from your landlord asks you to post your spare key to a new address.", attack: "phishing", real: "Phishing: a fake message that looks like it comes from someone you trust, asking for a click or a password." },
          { id: "padlock", analogy: "A thief puts his own padlock on your garage and leaves a note: pay me and I will send you the key.", attack: "ransomware", real: "Ransomware: malware encrypts (locks) your files and demands payment for the key." },
          { id: "courier", analogy: "A dishonest courier opens your parcels, reads the letters inside, and reseals them before delivery.", attack: "mitm", real: "Man-in-the-Middle: the attacker sits between two parties and reads or changes their messages in transit." },
          { id: "vest", analogy: "A man in a hi-vis vest says he is from the gas company, and the receptionist lets him into the server room.", attack: "social", real: "Social engineering: manipulating a person, not a system, into giving access or information." },
        ],
      },
    ],
    // Drill before the graded question: how a lure looks up close.
    "intro-cyber-q3": [
      {
        kind: "hotspot",
        title: "Spot the Lure",
        prompt: "A classmate forwarded this email to the academy's security desk. Find every red flag in it. Clicking a normal part tells you why it is fine.",
        artifact: "Inbox · Northport Academy Mail",
        parts: [
          { id: "from", style: "meta", text: "From: Northport Academy IT Desk <it-support@npacademy-helpdesk.co>", flag: true, note: "The name says Academy IT, but the address is on a domain the academy does not own." },
          { id: "to", style: "meta", text: "To: cohort-14@npacademy.org", flag: false, note: "A real group mailbox. Attackers often target group addresses to reach many people at once." },
          { id: "subject", style: "subject", text: "ACTION REQUIRED: your mailbox will be deleted in 2 hours", flag: true, note: "Urgency and a threat: designed to make you act before you think." },
          { id: "greet", style: "body", text: "Dear user,", flag: true, note: "Your own IT desk knows your name. A generic greeting suggests a mass mailing." },
          { id: "quota", style: "body", text: "Your mailbox has reached 99% of its storage quota.", flag: false, note: "Plausible on its own. Quota warnings are real, which is exactly why attackers copy them." },
          { id: "button", style: "button", text: "Keep my mailbox", href: "http://npacademy-mail.verify-quota.top/login", flag: true, note: "Hover it: the link goes to npacademy-mail.verify-quota.top, a look-alike login page, not the academy." },
          { id: "footer", style: "body", text: "Northport Academy IT · Building C · ext. 4400", flag: false, note: "Easy to copy from any real email. A footer proves nothing either way." },
        ],
      },
    ],
    // Drill before the graded alert: decode a different alert field by field.
    "intro-cyber-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of an Alert",
        prompt: "Before you work your first real alert, Maya walks you through a different one from last week. This is the raw detection, exactly as the antivirus wrote it.",
        source: "Microsoft Defender for Endpoint · detection on NPA-LIB-07",
        fields: [
          { key: "EventID", value: "1118" },
          { key: "ThreatName", value: "Worm:Win32/Phorpiex.A", label: "What was found", note: "The threat's name: type (Worm), platform (Win32) and family (Phorpiex). A worm copies itself to other places, such as USB sticks." },
          { key: "Severity", value: "Severe", label: "How bad", note: "The product's own rating. It helps you decide what to look at first, but it is never the whole story." },
          { key: "FilePath", value: "E:\\Photos\\holiday_photos.scr", label: "Where it was", note: "Drive E: on a library PC is a USB stick, not the hard disk. And .scr is a screensaver: a program dressed up as photos." },
          { key: "ProcessName", value: "explorer.exe", label: "What touched it", note: "explorer.exe is Windows' file browser: the user opened the stick's folder. A web browser here would mean a download from a website instead." },
          { key: "Action", value: "Remove", label: "What the antivirus did", note: "The response it attempted. Remove deletes the file; other actions you will meet are Quarantine (isolate it) and Allow." },
          { key: "ActionSuccess", value: "false", label: "Did it work?", note: "The most important field here. The removal FAILED, so the worm may still be on the stick and the PC." },
          { key: "ErrorDescription", value: "The process cannot access the file because it is being used by another process.", label: "Why it failed", note: "The file was in use, so it could not be deleted. A failed action is exactly when a human analyst has to step in." },
          { key: "UserName", value: "NPACADEMY\\j.rivera", label: "Who", note: "The account that was logged on. You will need it to talk to the user and check their other devices." },
          { key: "ComputerName", value: "NPA-LIB-07", label: "Which machine", note: "The host name. Library PCs are shared, so other users may have plugged in the same stick." },
          { key: "SHA256", value: "3b4f0c9e1a7d52e8b6c4f0a19d3e7b2c5a8f61d04e9b7c3a2f5d8e1b6c0a9f47" },
          { key: "DetectionTime", value: "2024-10-08T09:14:52.118Z" },
        ],
        summary: "On shared library PC NPA-LIB-07, j.rivera opened a USB stick; Defender found a worm disguised as holiday photos and tried to remove it, but the removal failed. The threat may still be active, so this alert is escalated, not closed.",
      },
    ],
    // ── Reading 3: real-world impact and career paths ──
    "intro-cyber-r3": [
      {
        kind: "match",
        title: "Brief the Council",
        prompt: "Northport's city council wants three budget lines justified. Match each request to the fact from the reading that backs it.",
        pairs: [
          { id: "mon", left: "A second analyst watching at night", right: "Breaches take around 200 days to detect", why: "The longer nobody is watching, the longer an attacker stays inside." },
          { id: "mfa", left: "Multi-factor sign-in for remote access", right: "One reused VPN password let DarkSide into Colonial Pipeline", why: "A single stolen password should never be enough on its own." },
          { id: "vendor", left: "Security checks on software suppliers", right: "SolarWinds hid a backdoor in a trusted update", why: "A supply chain attack comes through a vendor you already trust." },
        ],
      },
      {
        kind: "match",
        title: "Career Wall",
        prompt: "Today touched many jobs. Match each moment to the role that does it every day.",
        pairs: [
          { id: "ir", left: "Called in when the USB worm is confirmed, to contain it and clean the library PCs", right: "Incident Responder", why: "Incident response takes over once an attack is real." },
          { id: "pt", left: "Attacks the city's own network, with permission, to find weak spots first", right: "Penetration Tester", why: "An ethical hacker finds the holes before criminals do." },
          { id: "ti", left: "Tracks the group behind the fake IT-desk email and what it targets next", right: "Threat Intelligence Analyst", why: "Threat intelligence studies attackers, not alerts." },
          { id: "grc", left: "Checks the city follows the privacy laws for residents' data", right: "GRC Analyst", why: "Governance, risk and compliance turn laws into policy." },
          { id: "eng", left: "Builds and tunes the firewall and the SIEM", right: "Security Engineer", why: "Engineers build the tools the SOC works in." },
        ],
      },
    ],
  },
};
