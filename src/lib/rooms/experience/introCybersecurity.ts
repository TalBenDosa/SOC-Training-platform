import type { RoomExperience } from "./types";

// "Operation First Light" for the "intro-cybersecurity" room (rooms-batch-01.ts),
// the first room every learner meets. Script: docs/campaign/01-intro-cybersecurity.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Setting: the night shift at Mercy Bay Medical Center, a fictional regional
// hospital. Lab examples are deliberately different from the graded tasks: the
// reactor never uses a flooded records system (q1), the line-up never uses a
// poisoned software update (q2), the lure is an IT-desk mail, not a bank (q3),
// and the career wall leaves out the entry-level role (q4).
const FILMS = "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/intro-cybersecurity";

export const INTRO_CYBERSECURITY: RoomExperience = {
  roomId: "intro-cybersecurity",
  codename: "Operation First Light",
  theme: "hospital",
  handler: { name: "Marcus Hale", role: "SOC Lead, Night Shift" },
  briefing: [
    "02:40. Mercy Bay Medical Center. Four hundred beds, two theatres still running.",
    "Your first night in the SOC. The onboarding was meant to start at nine.",
    "It starts now. Wing by wing, we bring this hospital back online.",
    "Every building you light up, you are more of an analyst.",
  ],
  mission: "Your first night in the hospital SOC. Learn what you are defending, who attacks it and how, and bring the campus back online wing by wing before dawn.",
  estimate: "~35 min",
  look: { primary: "#2dd4bf", secondary: "#60a5fa", warn: "#f43f5e" },
  scene: "campus",
  layout: "campus",
  // Approved films in the lesson-videos bucket; names carry a content hash.
  story: {
    intro: { title: "First Light", src: `${FILMS}/first-light-intro-7375ab05.mp4`, poster: `${FILMS}/first-light-intro-0246468c.jpg` },
    afterStation: {
      emergency: { title: "Who Would Do This?", src: `${FILMS}/first-light-ch2-ab51c130.mp4`, poster: `${FILMS}/first-light-ch2-4db9564b.jpg` },
      archive: { title: "The Click", src: `${FILMS}/first-light-ch3-dfddec2e.mp4`, poster: `${FILMS}/first-light-ch3-e83ce4eb.jpg` },
      roof: { title: "Badge Issued", src: `${FILMS}/first-light-finale-b82456e8.mp4`, poster: `${FILMS}/first-light-finale-26406090.jpg` },
    },
  },
  stations: [
    {
      id: "reception",
      label: "Front Desk",
      tagline: "Map what this hospital has to defend before anyone attacks it",
      building: "reception",
      taskIds: ["intro-cyber-r1"],
    },
    {
      id: "emergency",
      label: "Emergency Department",
      tagline: "The ER screens are frozen. Learn the three things security protects",
      building: "emergency",
      taskIds: ["intro-cyber-r2", "intro-cyber-m1", "intro-cyber-q1"],
    },
    {
      id: "archive",
      label: "Security Archive",
      tagline: "Who would attack a hospital, and how? Work the line-up and the lure",
      building: "archive",
      taskIds: ["intro-cyber-q2", "intro-cyber-q3"],
    },
    {
      id: "wing",
      label: "Staffing Wing",
      tagline: "Your first real alert. Marcus is watching, you are deciding",
      building: "wing",
      taskIds: ["intro-cyber-la1"],
    },
    {
      id: "roof",
      label: "Command Roof",
      tagline: "Dawn. Brief the CIO and earn your SOC badge",
      building: "roof",
      taskIds: ["intro-cyber-r3", "intro-cyber-q4"],
      boss: true,
    },
  ],
  personas: {
    "intro-cyber-q1": {
      name: "Dr. Amira Saleh",
      role: "Head of Emergency Medicine",
      line: "Something is wrong with our systems and I have three patients on the way. Tell me what we lost.",
    },
    "intro-cyber-q2": {
      name: "Marcus Hale",
      role: "SOC Lead, Night Shift",
      line: "Old case from the archive, and a famous one. Read the file and tell me what kind of attacker we are looking at.",
    },
    "intro-cyber-q3": {
      name: "Marcus Hale",
      role: "SOC Lead, Night Shift",
      line: "This one came in on the training feed. Classify it the way you would in a ticket.",
    },
    "intro-cyber-q4": {
      name: "Daniel Brooks",
      role: "Chief Information Officer",
      line: "Good work tonight. Before I sign your badge: where does a career like yours usually start?",
    },
  },
  briefings: {
    // ── Reading 1: what cybersecurity is, the attack surface, a short history ──
    "intro-cyber-r1": [
      {
        kind: "sort",
        title: "Attack Surface Sweep",
        prompt: "The attack surface is everything an attacker can target. Marcus points at the campus map: sort every entry point he names by what it is.",
        buckets: [
          { id: "device", label: "Device" },
          { id: "service", label: "App or network" },
          { id: "person", label: "Person" },
        ],
        items: [
          { id: "pump", text: "A network-connected infusion pump in Ward 4", bucket: "device", why: "Medical devices on the network are computers too, and often run old software." },
          { id: "wifi", text: "The free visitor Wi-Fi in the lobby", bucket: "service", why: "A network anyone can join is part of what you defend." },
          { id: "portal", text: "The patient portal on the internet", bucket: "service", why: "An internet-facing application can be reached by anyone, day and night." },
          { id: "pc", text: "The shared PC at the front desk", bucket: "device", why: "A shared, always-on workstation is a classic foothold." },
          { id: "inbox", text: "A night nurse reading her email", bucket: "person", why: "People are on the attack surface: one convincing email reaches them directly." },
          { id: "phone", text: "The switchboard operator answering calls", bucket: "person", why: "A caller pretending to be IT is attacking a person, not a computer." },
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
    // ── Reading 2: the CIA triad (the actors and attacks are drilled below) ──
    "intro-cyber-r2": [
      {
        kind: "reactor",
        title: "Triad Reactor",
        prompt: "Incidents roll in on the conveyor. Route each one to the pillar it breaks before it reaches the end of the belt.",
        reactors: [
          { id: "c", label: "Confidentiality", sub: "Who can see it?" },
          { id: "i", label: "Integrity", sub: "Is it still true?" },
          { id: "a", label: "Availability", sub: "Can we use it now?" },
        ],
        items: [
          { id: "pdf", text: "A patient's lab results appear on a public forum", reactor: "c", why: "Private data reached people who should never see it." },
          { id: "dose", text: "An insulin dose in a chart changes from 5 to 50 units", reactor: "i", why: "The data was altered. Nobody lost access, but it can no longer be trusted." },
          { id: "xray", text: "Ransomware locks the radiology image server", reactor: "a", why: "Doctors cannot reach the images when they need them." },
          { id: "screen", text: "A visitor reads the ward's patient list off an unlocked screen", reactor: "c", why: "An unauthorised person saw private information." },
          { id: "invoice", text: "The bank account on a supplier invoice is quietly changed", reactor: "i", why: "A record was falsified, so a payment would go to the wrong place." },
          { id: "power", text: "A failed generator takes the lab system offline", reactor: "a", why: "Availability is not only about attackers: any outage counts." },
        ],
      },
    ],
    // Drill before the graded question: who attacks, and why.
    "intro-cyber-q2": [
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
          { id: "r3", evidence: ["Files on a clinic's servers were encrypted", "A note demands payment in Bitcoin", "Stolen files are threatened on a leak site"], suspect: "criminal", why: "Encrypt, extort, threaten to leak: the business model of organised crime." },
          { id: "r4", evidence: ["A billing clerk resigned last Friday", "On Thursday, the patient list was copied to a USB stick from her account"], suspect: "insider", why: "Legitimate access used against the organisation, right before leaving." },
          { id: "r5", evidence: ["A defence ministry's email was read for 14 months", "Custom tools, no ransom, nothing destroyed"], suspect: "nation", why: "Long, quiet, well-funded and after secrets: the signature of state espionage." },
        ],
      },
    ],
    // Drill before the graded question: how a lure looks up close.
    "intro-cyber-q3": [
      {
        kind: "hotspot",
        title: "Spot the Lure",
        prompt: "A nurse forwarded this email. Find every red flag in it. Clicking a normal part tells you why it is fine.",
        artifact: "Inbox · Mercy Bay Mail",
        parts: [
          { id: "from", style: "meta", text: "From: Mercy Bay IT Service Desk <it-support@mercybay-helpdesk.co>", flag: true, note: "The name says Mercy Bay IT, but the address is on a different domain the hospital does not own." },
          { id: "to", style: "meta", text: "To: night-nursing@mercybaymed.org", flag: false, note: "A real shared mailbox. Attackers often target group addresses to reach many people at once." },
          { id: "subject", style: "subject", text: "ACTION REQUIRED: your mailbox will be deleted in 2 hours", flag: true, note: "Urgency and a threat: designed to make you act before you think." },
          { id: "greet", style: "body", text: "Dear user,", flag: true, note: "Your own IT desk knows your name. A generic greeting suggests a mass mailing." },
          { id: "quota", style: "body", text: "Your mailbox has reached 99% of its storage quota.", flag: false, note: "Plausible on its own. Quota warnings are real, which is exactly why attackers copy them." },
          { id: "button", style: "button", text: "Keep my mailbox", href: "http://mercybay-mail.verify-quota.top/login", flag: true, note: "Hover it: the link goes to mercybay-mail.verify-quota.top, a look-alike login page, not the hospital." },
          { id: "footer", style: "body", text: "Mercy Bay IT · Building C · ext. 4400", flag: false, note: "Easy to copy from any real email. A footer proves nothing either way." },
        ],
      },
    ],
    // ── Reading 3: real-world impact and career paths ──
    "intro-cyber-r3": [
      {
        kind: "match",
        title: "Brief the CIO",
        prompt: "Daniel Brooks wants three things justified before he signs a budget. Match each request to the fact from the reading that backs it.",
        pairs: [
          { id: "mon", left: "A second analyst on nights", right: "Breaches take around 200 days to detect", why: "The longer nobody is watching, the longer an attacker stays inside." },
          { id: "mfa", left: "Multi-factor sign-in for remote access", right: "One reused VPN password let DarkSide into Colonial Pipeline", why: "A single stolen password should never be enough on its own." },
          { id: "vendor", left: "Security checks on software suppliers", right: "SolarWinds hid a backdoor in a trusted update", why: "A supply chain attack comes through a vendor you already trust." },
        ],
      },
      {
        kind: "match",
        title: "Career Wall",
        prompt: "Tonight touched many jobs. Match each moment to the role that does it every day.",
        pairs: [
          { id: "ir", left: "Called in after a breach is confirmed, to contain it and restore systems", right: "Incident Responder", why: "Incident response takes over once an attack is real." },
          { id: "pt", left: "Attacks the hospital's own network, with permission, to find weak spots first", right: "Penetration Tester", why: "An ethical hacker finds the holes before criminals do." },
          { id: "ti", left: "Tracks the group behind tonight's lure and what it targets next", right: "Threat Intelligence Analyst", why: "Threat intelligence studies attackers, not alerts." },
          { id: "grc", left: "Checks the hospital follows the privacy laws for patient data", right: "GRC Analyst", why: "Governance, risk and compliance turn laws into policy." },
          { id: "eng", left: "Builds and tunes the firewall and the SIEM", right: "Security Engineer", why: "Engineers build the tools the SOC works in." },
        ],
      },
    ],
  },
};
