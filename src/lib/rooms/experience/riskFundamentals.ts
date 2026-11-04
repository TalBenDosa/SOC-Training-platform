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
  scene: "riskcore",
  layout: "stage",
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
        kind: "sort",
        title: "Pull It Apart",
        prompt: "Each line is one piece of a risk story at Corvane. Is it the threat, the weakness, or the stakes?",
        buckets: [
          { id: "t", label: "Threat: who or what could cause harm" },
          { id: "v", label: "Vulnerability: the weakness" },
          { id: "i", label: "Impact: what it would cost" },
        ],
        items: [
          { id: "a", text: "A carding gang is selling skimmer kits built for our checkout platform", bucket: "t", why: "An actor with capability and intent: that is a threat." },
          { id: "b", text: "Store routers still use the factory admin password", bucket: "v", why: "A weakness waiting for someone to use it." },
          { id: "c", text: "If checkout goes down on Black Friday, we lose about $1.4M an hour", bucket: "i", why: "The consequence, in money. Impact depends on which asset and when." },
          { id: "d", text: "A flood in the region where our only data centre sits", bucket: "t", why: "Threats are not only people. A circumstance that can cause harm counts." },
          { id: "e", text: "Refunds over $5,000 need no second approval", bucket: "v", why: "A process gap is a vulnerability too, no CVE needed." },
          { id: "f", text: "The loyalty database holds 3.1M customers' home addresses", bucket: "i", why: "What would be exposed, and the fines and trust that come with it." },
        ],
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
        kind: "terminal",
        title: "Find What Nobody Remembers",
        prompt: "The asset inventory lists three internet-facing systems. Map Corvane from the outside, the way an attacker would, and compare.",
        shell: "bash",
        host: "marta@asm-box:~/corvane$",
        commands: [
          { match: "cat\\s+inventory\\.csv", help: "cat inventory.csv                                   what the inventory says is exposed",
            output: "hostname,owner,purpose,internet_facing\nshop.corvane.example,E-commerce,checkout and storefront,yes\nvpn.corvane.example,IT Infrastructure,staff remote access,yes\nmail.corvane.example,IT Infrastructure,mail gateway,yes" },
          { match: "subfinder\\s+.*corvane\\.example.*", help: "subfinder -d corvane.example -silent                  find subdomains from public sources",
            output: "shop.corvane.example\nvpn.corvane.example\nmail.corvane.example\npromo2019.corvane.example\njenkins.corvane.example\ntest-pos.corvane.example" },
          { match: "nmap\\s+.*(-il\\s+subs\\.txt|-iL\\s+subs\\.txt).*", help: "nmap -sV -Pn --top-ports 100 -iL subs.txt            what each host exposes",
            output: "Nmap scan report for shop.corvane.example (203.0.113.20)\n443/tcp  open  https     nginx\n\nNmap scan report for vpn.corvane.example (203.0.113.21)\n443/tcp  open  ssl/https GlobalProtect portal\n\nNmap scan report for mail.corvane.example (203.0.113.22)\n25/tcp   open  smtp      Postfix smtpd\n\nNmap scan report for promo2019.corvane.example (203.0.113.40)\n80/tcp   open  http      Apache httpd 2.4.29 ((Ubuntu))\n\nNmap scan report for jenkins.corvane.example (203.0.113.41)\n8080/tcp open  http      Jetty 9.4.43 (Jenkins 2.303)\n\nNmap scan report for test-pos.corvane.example (203.0.113.42)\n3389/tcp open  ms-wbt-server Microsoft Terminal Services" },
          { match: "curl\\s+.*jenkins\\.corvane\\.example.*", help: "curl -s http://jenkins.corvane.example:8080/api/json   does it ask for a login?",
            output: "{\"_class\":\"hudson.model.Hudson\",\"mode\":\"NORMAL\",\"nodeDescription\":\"the master Jenkins node\",\"numExecutors\":2,\"jobs\":[{\"name\":\"deploy-shop-prod\"},{\"name\":\"rotate-payment-keys\"}],\"useSecurity\":false}" },
        ],
        objectives: [
          { id: "count", task: "How many internet-facing hosts are missing from the inventory?", hint: "Compare cat inventory.csv with subfinder -d corvane.example -silent", answer: ["3", "three"], why: "promo2019, jenkins and test-pos: half of what the internet sees, nobody is tracking. You can't patch what you don't know exists." },
          { id: "rdp", task: "Which forgotten host exposes Remote Desktop to the internet?", hint: "nmap -sV -Pn --top-ports 100 -iL subs.txt", answer: ["test-pos.corvane.example", "test-pos"], why: "3389 open to the world: a standing invitation to password guessing. Close it before any CVE is ever named." },
          { id: "auth", task: "Does the Jenkins server require a login? (yes/no)", hint: "curl -s http://jenkins.corvane.example:8080/api/json", answer: ["no"], why: "useSecurity:false, and it holds jobs that deploy production and rotate payment keys. No vulnerability needed: it is open by configuration." },
          { id: "asr", task: "promo2019 is an old campaign site. What is the attack-surface-reduction move: patch Apache, or take it off the internet?", hint: "Does anyone still need it?", answer: ["take it off the internet", "take it offline", "decommission", "remove", "remove it", "take it down", "offline"], why: "Patching keeps a useless door in the wall. Removing it closes the door for every future flaw too." },
        ],
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
