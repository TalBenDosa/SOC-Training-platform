import type { RoomExperience } from "./types";

// "Operation Triage Board" for the "risk-fundamentals" room.
// Script: docs/campaign/13-risk-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Corvane Retail (fictional). Lab data differs from the graded tasks: the risk
// register never pairs a test VM with a payment database (q1); the CVSS and
// KEV drill is a fictional file-transfer CVE, not ac1's CVE-2026-24819 VPN
// finding; the surface scan finds forgotten hosts, not a phishing vector (q2);
// the integrations sheet asks what is connected and who approved it, not what
// changed (q3); and the triage board uses other hosts than f1's WEB-DEV03,
// HR-FS02 and PAY-API01.
export const RISK_FUNDAMENTALS: RoomExperience = {
  roomId: "risk-fundamentals",
  codename: "Operation Triage Board",
  theme: "risk",
  handler: { name: "Marta Novak", role: "Risk and Vulnerability Lead, Corvane Retail" },
  briefing: [
    "Corvane Retail. Two hundred stores, one e-commerce platform, and 4,312 open vulnerability findings this morning.",
    "Every scanner says 'critical'. Nobody can patch everything before the weekend.",
    "Marta Novak runs risk and vulnerability management. She doesn't rank by score; she ranks by threat, weakness and stakes together.",
    "Learn her board: what is risky, what is merely loud, and how much door you leave open.",
  ],
  mission: "Work the triage board: separate threat, vulnerability and impact, read what a CVSS vector measures and what KEV adds, map Corvane's external attack surface with a scanner, review what's plugged into the CRM, and rank a week's findings the way a risk lead does.",
  estimate: "~40 min",
  look: { primary: "#fb923c", secondary: "#38bdf8", warn: "#f43f5e" },
  scene: "facilityriskfundamentals",
  layout: "facility",
  story: {
    intro: { title: "4,312 Criticals", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-intro-fac4b870.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-intro-27ecf7a2.jpg" },
    afterStation: {
      score: { title: "Loud Is Not Risky", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-ch2-ac002665.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-ch2-2803e8a0.jpg" },
      surface: { title: "Doors Nobody Remembers", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-ch3-6b77d150.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-ch3-93b1ffc9.jpg" },
      board: { title: "The Board", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-finale-2dc05716.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/risk-fundamentals/triage-finale-61f9111a.jpg" },
    },
  },
  stations: [
    {
      id: "tvi",
      label: "Threat, Weakness, Stakes",
      topic: "Threat vs vulnerability vs impact · risk as their combination",
      tagline: "Pull a situation apart into its three components",
      building: "lab",
      taskIds: ["riskfund-r1"],
    },
    {
      id: "score",
      label: "Score vs Stakes",
      topic: "What CVSS measures · what KEV adds · why the same CVE differs by asset",
      tagline: "Read a CVSS vector and a KEV entry, then judge two servers",
      building: "archive",
      taskIds: ["riskfund-q1"],
    },
    {
      id: "surface",
      label: "Map the Surface",
      topic: "External, internal, human, physical, cloud surface · attack surface reduction",
      tagline: "Scan Corvane from the outside and find what nobody remembers",
      building: "control",
      taskIds: ["riskfund-r2"],
    },
    {
      id: "vector",
      label: "Surface or Vector",
      topic: "Every possible door vs the one door used · shadow IT",
      tagline: "Review who is plugged into the CRM",
      building: "office",
      taskIds: ["riskfund-q2", "riskfund-q3"],
    },
    {
      id: "board",
      label: "This Week's Queue",
      topic: "Prioritising real findings with threat, vulnerability and impact together",
      tagline: "Rank the findings the way the risk lead will",
      building: "ticket",
      taskIds: ["riskfund-ac1", "riskfund-m1", "riskfund-f1"],
      boss: true,
    },
  ],
  personas: {
    "riskfund-q1": { name: "Marta Novak", role: "Risk and Vulnerability Lead", line: "Same CVE, same score, two servers. Are they the same risk?" },
    "riskfund-q2": { name: "Marta Novak", role: "Risk and Vulnerability Lead", line: "The board keeps saying 'surface' and 'vector' as if they mean the same. Fix that." },
    "riskfund-q3": { name: "Marta Novak", role: "Risk and Vulnerability Lead", line: "Marketing plugged something into the CRM. No CVE, no attack. Has anything changed?" },
    "riskfund-ac1": { name: "Marta Novak", role: "Risk and Vulnerability Lead", line: "A 'medium' finding just got new intel attached. Does it jump the queue?" },
  },
  briefings: {
    // ── Reading 1: threat, vulnerability, impact ──
    "riskfund-r1": [
      {
        kind: "duel",
        title: "Threat Against Control",
        prompt: "Marta lays out five threats to Corvane. Each one is a threat meeting a weakness or a high-stakes asset. Play the control that cuts the exposed part of that exact story. Each card can be used once.",
        attacker: "Corvane's threat landscape",
        moves: [
          { id: "m1", move: "A carding gang sells skimmer kits built for our checkout", detail: "The threat is an actor with capability and intent. The weakness is third-party script that loads on the payment page without any check.", counter: "sri", hint: "You cannot arrest the gang. Which part of the story can Corvane change?", why: "The gang is the threat and you cannot remove it, so the control shrinks the weakness: an allow-list and integrity check on scripts on the payment page. Insurance pays after a loss but changes none of the three factors." },
          { id: "m2", move: "Scanners find store routers still on the factory admin password", detail: "Bots probe every address for default logins. Two hundred stores share one default credential.", counter: "uniquepw", hint: "The weakness here is not a missing patch.", why: "A default password is a weakness that needs no CVE. A unique credential per router, rotated, removes it. A security email to staff changes nothing about a router's login." },
          { id: "m3", move: "A flood hits the region where the only data centre sits", detail: "A non-human threat: a circumstance that can cause harm. Checkout would stop for days.", counter: "failover", hint: "You cannot stop weather. Reduce what the loss costs.", why: "Threats are not only people. With a second site and failover, the same flood costs hours, not days, so the control cuts impact. A longer password policy has nothing to do with water." },
          { id: "m4", move: "Refunds over $5,000 need no second approval", detail: "One clerk account can send large refunds with no check. This weakness has no CVE.", counter: "dualapp", hint: "A process gap, not a software flaw.", why: "A process gap is a vulnerability too. Requiring a second approver above a limit closes it for a fraud actor and a careless clerk alike. A vulnerability scanner will never see a business rule." },
          { id: "m5", move: "The loyalty database holds 3.1M customers' home addresses", detail: "If it is breached, the loss includes fines and trust. Nothing is wrong with the database today.", counter: "minimise", hint: "Nothing is broken. How do you make a breach cost less?", why: "Impact depends on what is stored. Minimising, encrypting and expiring addresses cuts the cost of any future breach. Making the scanner stricter finds weaknesses, not stakes." },
        ],
        cards: [
          { id: "sri", name: "Script allow-list and integrity check on checkout", effect: "Only approved scripts load on the payment page." },
          { id: "uniquepw", name: "Unique rotated router credentials", effect: "Every device gets its own secret." },
          { id: "failover", name: "Second site with failover", effect: "Service moves to another location if one fails." },
          { id: "dualapp", name: "Second approver above a refund limit", effect: "Large payments need two people." },
          { id: "minimise", name: "Store less and encrypt what remains", effect: "Reduces what a breach could expose." },
          { id: "insure", name: "Cyber insurance policy", effect: "Pays part of the cost after a loss." },
          { id: "email", name: "Weekly all-staff security email", effect: "Reminds everyone to stay careful." },
        ],
        lesson: "Risk is threat, weakness and stakes together. You rarely control the threat, so a good control shrinks the weakness or the impact. Insurance and awareness emails feel like action and change none of the three.",
      },
      {
        kind: "worksheet",
        title: "Read the Risk Register",
        prompt: "Marta's register rates each component Low, Medium or High. Risk needs all three. Read the register and answer.",
        caption: "Corvane risk register · Q4 review · qualitative ratings",
        columns: ["ID", "scenario", "threat", "vulnerability", "impact"],
        rows: [
          ["R-07", "Skimmer injected into checkout JavaScript", "High", "Medium", "High"],
          ["R-11", "Old Windows 7 kiosk in the staff canteen, offline, no network", "Low", "High", "Low"],
          ["R-14", "Ransomware via the store remote-support tool", "High", "High", "High"],
          ["R-19", "Website defacement of the archived 2019 campaign page", "Medium", "Medium", "Low"],
        ],
        questions: [
          { id: "top", q: "Which ID is the highest risk?", hint: "The one with no Low anywhere.", answer: ["R-14"], why: "High threat, high weakness, high stakes: every factor is pushing the same way." },
          { id: "loud", q: "Which ID has the worst vulnerability rating but sits near the bottom of the list?", hint: "A High weakness that nobody can reach and nothing depends on.", answer: ["R-11"], why: "An unpatched Windows 7 box sounds terrible, but offline and low-impact, its risk collapses. Weakness alone isn't risk." },
          { id: "zero", q: "If R-07's threat drops to zero tomorrow (the gang is arrested and the kit vanishes), what happens to its risk? (rises / falls / same)", hint: "Think of the multiplication sign.", answer: ["falls", "drops", "falls toward zero", "goes down"], why: "Take any factor to zero and the product goes with it. That is the point of the T x V x I shorthand, not the arithmetic." },
        ],
      },
    ],
    // Drill before q1: what a CVSS score measures, and what KEV adds.
    "riskfund-q1": [
      {
        kind: "anatomy",
        title: "Anatomy of a CVSS Vector",
        prompt: "A score of 9.8 is a summary of eight answers about the flaw itself. Read them, and notice what is missing.",
        source: "CVSS v3.1 · base vector of a scanner finding",
        fields: [
          { key: "CVSS", value: "3.1", label: "Version", note: "v3.1 base scores run 0.0 to 10.0." },
          { key: "AV", value: "N", label: "Attack Vector", note: "Network: reachable remotely. L (local) or P (physical) would lower the score." },
          { key: "AC", value: "L", label: "Attack Complexity", note: "Low: no special conditions needed." },
          { key: "PR", value: "N", label: "Privileges Required", note: "None: no login needed first." },
          { key: "UI", value: "N", label: "User Interaction", note: "None: no one has to click anything." },
          { key: "S", value: "U", label: "Scope", note: "Unchanged: the damage stays in the vulnerable component." },
          { key: "C/I/A", value: "H/H/H", label: "Damage to the component", note: "High loss of confidentiality, integrity and availability." },
          { key: "Base score", value: "9.8 (Critical)", label: "The summary", note: "Technical severity only. Nothing here says whether anyone is exploiting it, or what this asset is worth to you." },
        ],
        summary: "CVSS rates the flaw, the same on every machine. Who is exploiting it is a threat question, and what this machine holds is an impact question. Now judge two servers with the same score.",
      },
      {
        kind: "anatomy",
        title: "Anatomy of a KEV Entry",
        prompt: "CISA's Known Exploited Vulnerabilities catalog adds the piece CVSS leaves out: proof of use in the wild. Here's an entry, field by field.",
        source: "CISA KEV catalog · JSON record (fictional CVE for training)",
        fields: [
          { key: "cveID", value: "CVE-2026-31144", label: "Which flaw" },
          { key: "vendorProject", value: "Northgate", label: "Vendor" },
          { key: "product", value: "SecureFile Transfer" },
          { key: "dateAdded", value: "2026-10-21", label: "Confirmed exploited", note: "The day CISA had reliable evidence of exploitation in the wild." },
          { key: "shortDescription", value: "SQL injection in the web transfer interface allows unauthenticated remote code execution." },
          { key: "requiredAction", value: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.", label: "What to do" },
          { key: "dueDate", value: "2026-11-11", label: "Deadline", note: "Binding for US federal agencies; a useful yardstick for everyone else." },
          { key: "knownRansomwareCampaignUse", value: "Known", label: "Ransomware?", note: "Known: ransomware crews are using it. The threat component, in one word." },
        ],
        summary: "KEV answers 'is anyone using this?' with evidence. A medium CVSS on a KEV-listed, internet-facing system can outrank a 9.8 that nobody exploits.",
      },
    ],
    // ── Reading 2: attack surface ──
    "riskfund-r2": [
      {
        kind: "sort",
        title: "Which Surface?",
        prompt: "Entry points from Corvane's inventory. Sort each into the part of the attack surface it belongs to.",
        buckets: [
          { id: "ext", label: "External" },
          { id: "int", label: "Internal" },
          { id: "hum", label: "Human" },
          { id: "phy", label: "Physical" },
          { id: "cloud", label: "Cloud / SaaS" },
        ],
        items: [
          { id: "a", text: "shop.corvane.example checkout API", bucket: "ext", why: "Internet-facing: anyone can send it requests." },
          { id: "b", text: "\\\\FS-HQ01\\Finance share, open to Domain Users", bucket: "int", why: "Reachable once someone is inside the network." },
          { id: "c", text: "Store managers who approve supplier bank changes by email", bucket: "hum", why: "People who can be tricked into acting for an attacker." },
          { id: "d", text: "An unlocked network cabinet in the Leeds store stockroom", bucket: "phy", why: "Plug in a cable, and you're on the store network." },
          { id: "e", text: "A Salesforce org with 14 connected apps", bucket: "cloud", why: "Third-party services and their integrations are entry points too." },
          { id: "f", text: "svc_pos service account used by every till", bucket: "int", why: "An internal identity with wide reach: surface for anyone already inside." },
        ],
      },
      {
        kind: "defuse",
        title: "Doors Nobody Remembers",
        prompt: "Marta's outside-in scan of Corvane is back and the weekend freeze starts in minutes. Four calls on forgotten internet-facing hosts. Cut the right wire before the clock runs out.",
        device: "FREEZE COUNTDOWN",
        seconds: 80,
        rounds: [
          {
            id: "count",
            state: "The inventory lists 3 internet-facing hosts. A public-source subdomain search shows 6 names resolving to Corvane addresses.",
            wires: [
              { id: "a", label: "Treat the inventory as the source of truth and re-scan only those 3" },
              { id: "b", label: "Scan all 6 and give each unknown host an owner" },
              { id: "c", label: "Wait for the next quarterly asset review" },
            ],
            cut: "b",
            hint: "What does an attacker see?",
            why: "Half of what the internet sees is untracked, and you cannot patch what you do not know exists. Map from the outside, then assign an owner to every host that turns up.",
          },
          {
            id: "rdp",
            state: "test-pos.corvane.example answers on 3389 from the whole internet. No CVE is listed for the service today.",
            wires: [
              { id: "a", label: "Wait until a CVE is published for it" },
              { id: "b", label: "Require a 20-character password on the local accounts" },
              { id: "c", label: "Close 3389 to the internet today" },
            ],
            cut: "c",
            hint: "Not every risk starts with a CVE.",
            why: "Remote Desktop open to the world is a standing invitation to password guessing, no CVE needed. Closing the exposure comes before any naming. A long password helps but leaves the door in the wall.",
          },
          {
            id: "auth",
            state: "jenkins.corvane.example:8080 returns its job list with no login. Jobs include deploy-shop-prod and rotate-payment-keys. The setting useSecurity is false.",
            wires: [
              { id: "a", label: "Patch Jenkins to the newest release" },
              { id: "b", label: "Put a WAF rule in front of the login page" },
              { id: "c", label: "Pull it off the internet and switch authentication on" },
            ],
            cut: "c",
            hint: "There is no login page to protect.",
            why: "This is open by configuration, not by flaw, so a patch changes nothing. A login-page WAF rule protects a page that does not exist. Restrict access and turn security on.",
          },
          {
            id: "asr",
            state: "promo2019.corvane.example is a 2019 campaign site on an old Apache build. Nobody has edited it in a year, and no team lists it.",
            wires: [
              { id: "a", label: "Take it off the internet" },
              { id: "b", label: "Patch Apache and keep the site up" },
              { id: "c", label: "Add it to the inventory and move on" },
            ],
            cut: "a",
            hint: "Ask who still needs it.",
            why: "Patching keeps a useless door in the wall. Removing it closes the door for every future flaw too: that is attack surface reduction. Logging it in the inventory only documents the exposure.",
          },
        ],
        lesson: "You can only defend what you know exists. Map the surface from the outside, close doors nobody needs, and fix open-by-configuration exposures as seriously as CVEs.",
      },
    ],
    // Drill before q3: what is connected to the CRM, and who approved it.
    "riskfund-q3": [
      {
        kind: "worksheet",
        title: "Who's Plugged Into the CRM?",
        prompt: "An export of every app with API access to Corvane's CRM. Read who approved what.",
        caption: "CRM connected apps · export 2026-11-04",
        columns: ["app", "publisher verified", "permission", "approved by", "security review"],
        rows: [
          ["Corvane Data Sync", "Yes (Corvane IT)", "Read/write all records", "IT change CHG-4471", "Done 2025-03"],
          ["MailBlast Pro", "Yes", "Read contacts", "IT change CHG-5102", "Done 2026-01"],
          ["QuickSign", "Yes", "Read opportunities", "Sales manager (self-service)", "None"],
          ["DealPulse AI", "No", "Read all customer records", "Sales rep (self-service)", "None"],
        ],
        questions: [
          { id: "worst", q: "Which app can read every customer record, from an unverified publisher, with no review?", hint: "Look for all three warning signs on one row.", answer: ["DealPulse AI", "dealpulse"], why: "Broad access, unknown vendor, nobody looked. Its security now decides who can reach your customers." },
          { id: "n", q: "How many apps were connected without a security review?", hint: "Count 'None' in the last column.", answer: ["2", "two"], why: "Self-service consent lets anyone add a door. Each of these is surface the security team never saw being built." },
        ],
      },
    ],
    // Drill before the graded flag: a different week's findings, triaged.
    "riskfund-f1": [
      {
        kind: "queue",
        title: "Patch Triage Board",
        prompt: "Last week's board, before you rank this week's. The severity column is the scanner's CVSS. Decide each one from threat, weakness and stakes.",
        console: "Vulnerability triage · Corvane Retail · week 44",
        actions: [
          { id: "now", label: "Emergency patch now", tone: "escalate" },
          { id: "window", label: "Next maintenance window", tone: "close" },
        ],
        alerts: [
          { id: "lab", time: "Mon", severity: "Critical", rule: "CVSS 9.1 · OpenSSH pre-auth flaw", entity: "LAB-ML05",
            fields: [{ k: "exposure", v: "isolated lab VLAN" }, { k: "data", v: "synthetic test sets" }, { k: "exploitation", v: "none reported" }, { k: "status", v: "decommission on 2026-11-15" }],
            context: "A research box nobody depends on, being switched off in two weeks.", answer: "window", why: "Critical on paper, but no threat and no stakes. Isolate it and let the decommission close it." },
          { id: "mft", time: "Tue", severity: "Medium", rule: "CVSS 6.1 · file transfer web UI", entity: "MFT-EDGE01",
            fields: [{ k: "exposure", v: "internet-facing" }, { k: "data", v: "supplier invoices, payroll files" }, { k: "KEV", v: "listed · ransomware use Known" }],
            context: "The supplier file-transfer gateway, with a flaw crews are exploiting right now.", answer: "now", why: "Medium score, maximum risk: active exploitation, reachable from the internet, sensitive data behind it." },
          { id: "print", time: "Wed", severity: "High", rule: "CVSS 8.8 · print spooler", entity: "PRN-HQ02",
            fields: [{ k: "exposure", v: "internal only" }, { k: "exploitation", v: "proof of concept public, no attacks seen" }, { k: "data", v: "print queue" }],
            context: "An internal print server with a public PoC.", answer: "window", why: "Worth watching, since a public PoC raises the likelihood, but internal and low-stakes: the scheduled window is right." },
          { id: "portal", time: "Thu", severity: "High", rule: "CVSS 7.5 · auth bypass in customer portal", entity: "PORTAL-WEB02",
            fields: [{ k: "exposure", v: "internet-facing" }, { k: "data", v: "customer accounts, saved cards (tokenised)" }, { k: "exploitation", v: "vendor confirms attacks against retailers" }],
            context: "The customer account portal, with confirmed attacks against other retailers.", answer: "now", why: "Active threat, open door and customer data at stake: all three are high." },
        ],
      },
    ],
  },
};
