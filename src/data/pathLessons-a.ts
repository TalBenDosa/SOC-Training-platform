// Learning Path lessons — Foundations module A
const lessons = [
  {
    "id": "local-lesson-4",
    "slug": "what-a-soc-is-and-the-analyst-role",
    "title": "What a SOC Is and What a Security Analyst Actually Does All Day",
    "topic": "SOC Fundamentals",
    "difficulty": "beginner",
    "kind": "lesson",
    "intro": "Before you can investigate a single alert, you need a clear mental picture of the world you are walking into. A Security Operations Center, or SOC, is the team and the room where an organization watches for signs that someone is trying to break in, steal data, or cause damage. If you have ever seen a bank with a wall of camera monitors and a guard who watches them around the clock, you already understand the core idea. The SOC is that security desk — except instead of watching hallways and doors, it watches computers, servers, cloud accounts, and network traffic. The alerts that appear on the analyst's screen are the digital equivalent of a motion sensor tripping or a door being forced.\n\nThis lesson gives you the map of that world. You will learn what a SOC monitors and why companies spend serious money to run one every hour of every day. You will learn the difference between a Tier 1, Tier 2, and Tier 3 analyst, and where you fit as a beginner. You will follow an alert from the moment a detection rule fires to the moment a human decides whether it is harmless, worth watching, or a genuine attack. Most importantly, you will start building the single habit that separates good analysts from button-clickers: asking the right questions of every alert instead of blindly closing it.\n\nBy the end, you will be able to describe what happens on a SOC shift, explain why an alert is not the same thing as an incident, and apply a simple three-way verdict — benign, suspicious, or malicious — to what you see. You will also understand why the ticket you write is the real product of your job. This is the foundation everything else in your training rests on, so let the vocabulary sink in. Once you know the shape of the room, every log, rule, and investigation you learn later will have a place to hang.",
    "sections": [
      {
        "heading": "What a Security Operations Center Actually Is",
        "content": "A Security Operations Center is a team of people, supported by technology and defined processes, whose job is to detect and respond to cyber threats against an organization. Think of it exactly like the 24/7 security desk in the lobby of a large building. That desk has cameras pointed at every entrance, sensors on the doors, and a guard whose entire job is to notice when something is wrong and decide what to do about it. The SOC does the same thing, but the building is the company's entire digital estate: laptops, servers, email, cloud accounts, applications, and the network that connects them all.\n\nThe reason companies run a SOC is simple. Attacks do not happen only during business hours, and no single defensive tool catches everything. A firewall blocks a lot, antivirus blocks a lot more, but determined attackers get past those walls constantly. When they do, the only thing standing between a quiet break-in and a catastrophic data breach is a human who notices the signs early and acts. That human is the SOC analyst. The cost of NOT having someone watching is measured in stolen customer records, ransomware that shuts down the business, and regulatory fines — which is why even mid-sized companies now build or rent a SOC.\n\n### What the SOC actually watches\n\nThe SOC does not literally watch computers with its eyes. Instead, every important system is configured to send a record of what it does — a **log** — to a central platform called a **SIEM** (Security Information and Event Management). A login is a log. A file being opened is a log. A firewall allowing a connection is a log. The SIEM collects millions of these per day, and detection rules run across them looking for patterns that suggest trouble: a user logging in from two countries an hour apart, a program that antivirus flagged, a burst of failed passwords. When a rule matches, it produces an **alert**, and that alert lands in the analyst's queue.\n\n### The three ingredients of a SOC\n\nEvery SOC, whether it is three people or three hundred, runs on three things. **People** are the analysts and their managers who make judgment calls no machine can. **Process** is the set of agreed steps for handling an alert, escalating a problem, and communicating during a crisis — so that the response does not depend on who happens to be on shift. **Technology** is the SIEM, the EDR (Endpoint Detection and Response tool on every laptop), the ticketing system, and the threat-intelligence feeds. A SOC that has great tools but no process produces chaos; a SOC with great process but no skilled people produces slow, shallow investigations. As an analyst you are the most valuable of the three, because you supply the one thing that cannot be automated: the ability to ask why.\n\nWhen you start, do not worry about knowing every tool. Worry about understanding the loop: systems generate logs, the SIEM turns suspicious logs into alerts, and analysts turn alerts into decisions. Everything you learn from here fits inside that loop.",
        "codeExample": "// The core SOC loop, in plain terms\n// 1. Systems emit LOGS (raw records of everything that happens)\nlaptop, server, firewall, cloud, email  --->  SIEM\n\n// 2. The SIEM stores logs and runs DETECTION RULES over them\nrule: \"5+ failed logins then 1 success from same IP in 10 min\"\n\n// 3. A matching rule produces an ALERT in the analyst QUEUE\nALERT #48213  severity=Medium  \"Possible password guessing - user jsmith\"\n\n// 4. A human ANALYST investigates and reaches a VERDICT\nverdict = benign | suspicious | malicious\n\n// Remember: an ALERT is a question the machine is asking you.\n// Your job is to answer it, not just to close it."
      },
      {
        "heading": "The Analyst Tiers and the Alert Lifecycle",
        "content": "SOCs organize their analysts into tiers, a bit like an emergency room sorts staff by how serious a case is. You will almost always start at **Tier 1**, and understanding the tiers tells you exactly what is expected of you and who you hand work to when it gets too big.\n\n### The three tiers\n\n**Tier 1 analysts** are the front line. They watch the alert queue, do the first look at each alert (called **triage**), and decide whether it is nothing, needs more digging, or must be escalated. The Tier 1 skill is speed with judgment: closing the obvious false alarms quickly and correctly, and recognizing the real ones without wasting an hour on each. **Tier 2 analysts** take the alerts Tier 1 escalates. They investigate deeper, pull in more data sources, and confirm whether a real incident is underway. **Tier 3 analysts** are the most experienced — often called incident responders or threat hunters. They handle confirmed serious incidents, hunt for threats no rule has caught yet, and help build better detections. Think of it as a hospital: Tier 1 is triage at the door, Tier 2 is the treating doctor, Tier 3 is the specialist surgeon.\n\n### How an alert is born and where it goes\n\nAn alert begins its life when a detection rule matches a log pattern in the SIEM. The moment it appears, a clock starts. **MTTD** (Mean Time To Detect) measures how long it took to notice the threat in the first place — often driven by how good the detection rules are. **MTTR** (Mean Time To Respond) measures how long from alert to containment. Both are headline numbers SOC managers live and die by, because every extra minute an attacker has inside the network is more damage done.\n\n### SLAs and escalation\n\nBecause time matters so much, SOCs commit to **SLAs** (Service Level Agreements) — promises about how fast an alert of a given severity gets looked at. A Critical alert might carry a 15-minute SLA; a Low might be four hours. As a Tier 1 analyst, your SLA clock is always ticking, and part of the discipline is working the highest-severity, oldest alerts first. **Escalation** is the formal act of handing an alert up a tier because it is beyond your scope or authority. Good escalation is not a failure — it is exactly what the process asks you to do. Escalating a genuine incident quickly is far better than sitting on it because you were unsure. The questions to ask yourself are: Do I have enough evidence that this is real? Is it bigger than one host or one user? Have I hit the limit of what I am trained or permitted to do? If yes to any, escalate — and write down why.\n\nUnderstanding this structure keeps you from two beginner mistakes: trying to solve everything yourself and drowning, or escalating everything and becoming noise. The tiers exist so that each analyst works at the right depth, and the alert lifecycle exists so that nothing falls through the cracks.",
        "codeExample": "// Example SLA and escalation matrix a Tier 1 analyst works to\n\n// SEVERITY   FIRST-TOUCH SLA   TYPICAL ACTION\n// Critical   15 minutes        Investigate now, page Tier 2/on-call\n// High       30 minutes        Investigate now, escalate if confirmed\n// Medium     2 hours           Triage, close or escalate\n// Low        4 hours           Triage in batches\n\n// Key timing metrics your manager watches:\nMTTD = time from attacker action  ->  alert fires   // detection speed\nMTTR = time from alert fires       ->  threat contained  // response speed\n\n// Escalate to Tier 2 when ANY of these is true:\n//  [ ] Evidence points to a real compromise, not a false alarm\n//  [ ] More than one host, account, or system is involved\n//  [ ] The action needed is beyond your permissions (e.g. isolate a server)\n//  [ ] You have exhausted your playbook and it is still unclear"
      },
      {
        "heading": "A Day on Shift: The Queue and the Benign / Suspicious / Malicious Decision",
        "content": "A SOC shift is built around one central object: the **queue**. The queue is simply the list of alerts waiting to be looked at, usually shown as a sortable table in the SIEM or ticketing tool. Each row is an alert with a severity, a timestamp, a short title, and a status. Your shift, at its heart, is the act of working that queue down — picking up alerts, deciding what they are, and moving them to a resolved state, all while new ones keep arriving.\n\n### How you work the queue\n\nYou do not work top to bottom. You work by priority: highest severity first, and within a severity, oldest first so nothing breaches its SLA. For each alert you perform **triage** — a fast first assessment to answer one question: what is this, really? Triage is not a full investigation. It is the quick read that tells you whether to close the alert, dig deeper, or hand it up. A good Tier 1 analyst can triage many routine alerts an hour, because most of what a SIEM produces is noise: a scheduled scanner, an admin doing legitimate maintenance, a mistyped password. The art is closing that noise fast and correctly while catching the one alert in fifty that is real.\n\n### The three-way verdict\n\nEvery alert you triage ends in one of three verdicts, and learning to reach for these three words is one of the most important habits you will build.\n\n**Benign** means it is legitimate, expected activity that happens to have tripped a rule. The failed logins were the user fat-fingering their password, then getting it right. You close it as a false positive, and ideally you note why so the rule can be tuned. **Suspicious** means you cannot yet prove it is bad, but you cannot prove it is fine either. Something is off — an unusual time, an unfamiliar location, a process you do not recognize — and it deserves more investigation or a second pair of eyes. This is the honest middle, and it is where careful analysts live; there is no shame in a suspicious verdict as long as you say what would resolve it. **Malicious** means the evidence shows genuine attacker activity: confirmed malware, a real intrusion, data leaving the building. This becomes an incident and gets escalated immediately.\n\nThe mistake beginners make is forcing every alert into benign or malicious because suspicious feels like indecision. It is not. Suspicious is a valid, professional verdict that says the evidence is incomplete, and it triggers the right next step rather than a premature close.\n\n### Shift handover\n\nA SOC never sleeps, so shifts overlap and hand off. **Handover** is the short structured briefing where the outgoing shift tells the incoming shift what is still open, what is being watched, and what to expect. A good handover means an investigation you started at 2pm is not dropped at 3pm when you go home. Always leave your open tickets in a state the next analyst can pick up: current findings written down, next step stated, nothing living only in your head.",
        "codeExample": "// A slice of a real alert queue as a Tier 1 analyst sees it\n\n// ID     SEV       AGE    TITLE                                STATUS\n// 48219  Critical  0:04   EDR: ransomware behavior on FIN-PC7  New\n// 48211  High      0:22   Impossible travel - user a.cohen     New\n// 48207  Medium    1:10   Multiple failed logins - svc_backup  In progress\n// 48190  Medium    1:48   New admin group member added         New\n// 48155  Low       3:30   Port scan blocked at perimeter       New\n\n// Work order: 48219 first (Critical, oldest-critical), then 48211...\n\n// For each, reach ONE verdict:\ntriage(48207) -> benign?     // svc_backup mistyped, then succeeded on schedule\ntriage(48211) -> suspicious? // login Tel Aviv 09:00, London 09:40 - needs checking\ntriage(48219) -> malicious?  // files being mass-encrypted - ESCALATE NOW"
      },
      {
        "heading": "The Questions a Good Analyst Asks Every Single Alert",
        "content": "Here is the secret that no tool teaches you: the difference between an analyst who catches real attacks and one who just clears the queue is not which buttons they press. It is the questions they ask. An alert is a machine noticing that something matched a pattern. It cannot tell you whether that something is normal for THIS user, THIS host, THIS time of day. Only a human asking the right questions can. Learn to run this questioning framework on every alert and you will already be ahead of many working analysts.\n\n### Is this normal for this user or host?\n\nThe first and most powerful question is about **baseline** — what is normal here? An administrator running PowerShell at 2am might be routine for that admin and alarming for an accountant. A login from Germany is unremarkable for a sales rep who travels and a red flag for someone who has never left the country. Before you decide anything is bad, ask: is this behavior unusual FOR THIS SPECIFIC ENTITY? You answer it by looking at that user's or host's history. Most real detections come from spotting a deviation from a person's own normal, not from the activity being exotic in the abstract.\n\n### What actually fired the rule?\n\nNever trust the alert title alone. Open it and ask: which exact log, which exact field, made this rule match? A title that says \"Suspicious PowerShell\" means nothing until you read the actual command line that ran. Understanding precisely what tripped the detection tells you whether the rule caught something real or misfired on a benign edge case. This is also how you learn — every alert you open and truly read makes the next one faster.\n\n### What happened before and after?\n\nAn alert is a single frame from a movie. Attacks are sequences: a phishing click, then a download, then a suspicious process, then a connection out. Always widen the timeline. Ask: what did this user or host do in the fifteen minutes BEFORE the alert, and what happened AFTER? A lone failed login is nothing; a failed login followed by a success followed by a new admin account being created is an attack unfolding. Pivoting on time is how you turn one alert into the story around it.\n\n### Who else is affected?\n\nAsk whether this is isolated or part of something bigger. Did the same suspicious IP touch other users? Did the same malware hash appear on other laptops? Scope is what separates a contained problem from a spreading one, and it is often the question that turns a Medium alert into a Critical incident.\n\n### What is the impact if this is real?\n\nFinally, ask the business question: if this is genuinely malicious, what is at stake? An alert on a test machine with no data is very different from the same alert on the domain controller or the finance server. Impact drives urgency and escalation. Together these five questions — is it normal for this entity, what fired the rule, what came before and after, who else is affected, what is the impact — form the spine of every investigation you will ever do. Memorize them now, and apply them even when an alert looks obviously benign; the discipline of asking is what catches the clever attack disguised as noise.",
        "codeExample": "// The analyst's five-question framework - run it on EVERY alert\n\n// 1. NORMAL FOR THIS ENTITY?\n//    -> Pull the user's / host's history. Is this a deviation from THEIR baseline?\n// 2. WHAT FIRED THE RULE?\n//    -> Open the raw log. Read the exact command / field / value that matched.\n// 3. BEFORE & AFTER?\n//    -> Widen the timeline +/- 15-60 min. What is the sequence around this event?\n// 4. WHO ELSE?\n//    -> Pivot on the IP, hash, user, or domain. Is anyone/anything else touched?\n// 5. IMPACT IF REAL?\n//    -> What system/data is at stake? Test box vs. domain controller changes everything.\n\n// Worked example - alert: \"Login from new country - user a.cohen\"\n// Q1: a.cohen has only ever logged in from Israel        -> deviation, note it\n// Q2: rule fired on GeoLocation.country_name = \"Russia\"   -> confirmed foreign login\n// Q3: 40 min earlier, same account failed login 12 times  -> looks like guessing succeeded\n// Q4: same source IP also hit b.levi and c.mizrahi         -> NOT isolated - scope grows\n// Q5: a.cohen is in Finance with access to payroll         -> high impact\n// Verdict: MALICIOUS -> escalate as likely account compromise"
      },
      {
        "heading": "From Alert to Handoff: Documentation, Escalation, and Why It Matters",
        "content": "You have triaged the alert, asked your questions, and reached a verdict. You are not done. The final and most underrated part of the job is writing it down. In a SOC, **the ticket is the product**. Your investigation lives in your head for an hour and then it is gone; the ticket is what survives, what the next analyst reads, what an auditor examines a year later, and what turns a scattered set of clicks into defensible, repeatable work.\n\n### Why the ticket is the product\n\nImagine the finest investigation in the world that ends with the analyst closing the alert and writing nothing. To everyone else, it never happened. If the same alert fires next week, the next analyst starts from zero. If a breach is later discovered, there is no record of what was checked. A clear ticket, by contrast, is a gift to your future self and your team: it captures what you saw, what you concluded, and why. Analysts are ultimately judged not by how many alerts they closed but by the quality of the record they left behind.\n\n### What good documentation contains\n\nA solid ticket answers the questions someone else would ask without them having to ask you. State **what the alert was** and when it fired. State **what you checked** — the specific logs, users, hosts, and IPs you looked at. State **what you found**, including the raw evidence (a log line, a command, a source IP) rather than just your impression. State your **verdict** — benign, suspicious, or malicious — and crucially the **reasoning** behind it. And state the **action taken or recommended**: closed as false positive, escalated to Tier 2, host isolated. Write it so a colleague who has never seen this alert can follow your logic end to end. Avoid vague phrases like \"looks fine\" — say why it looks fine.\n\n### When and how to escalate\n\nEscalation is the formal handoff of an alert to a higher tier or another team, and doing it well is a core Tier 1 skill. Escalate when the evidence points to a real incident, when the scope is beyond a single host or user, or when the response needed exceeds your permissions — such as isolating a machine or disabling an account. The key is that escalation must carry your documentation with it. A bare \"this looks bad, help\" forces the next analyst to redo your work. A good escalation says: here is the alert, here is what I checked, here is why I believe it is malicious, here is what I recommend. That lets Tier 2 act in minutes instead of restarting the clock.\n\n### The mindset to carry forward\n\nThink of every ticket as evidence you might have to defend. Would it hold up if a manager, an auditor, or a courtroom read it? That standard keeps your documentation honest and complete. The habits from this lesson — working the queue by priority, reaching a clear three-way verdict, asking the five questions, and writing a ticket that stands on its own — are the whole job in miniature. Every advanced skill you learn later is just a deeper version of this same loop. Master the loop, and you have become a SOC analyst.",
        "codeExample": "// A well-formed triage ticket - the actual PRODUCT of your shift\n\n// TICKET #48211  |  Verdict: MALICIOUS  |  Escalated to: Tier 2\n// -----------------------------------------------------------------\n// ALERT:     Impossible travel - user a.cohen (fired 09:42, Medium)\n// CHECKED:\n//   - Sign-in logs for a.cohen (Microsoft Entra ID, formerly Azure AD), last 30 days\n//   - Source IP 185.x.x.x reputation and other users it touched\n//   - Failed-login history preceding the success\n// FOUND:\n//   - 12 failed logins 09:00-09:38 from 185.x.x.x, then 1 success 09:40\n//   - a.cohen has NEVER signed in from outside Israel before\n//   - Same IP also authenticated against b.levi and c.mizrahi\n//   - a.cohen has access to payroll data (high impact)\n// VERDICT:   Malicious - likely successful password-guessing / account takeover\n// REASONING: Deviation from user baseline + brute-force pattern + multi-user scope\n// RECOMMEND: Disable a.cohen session, force password reset + MFA,\n//            investigate b.levi and c.mizrahi for same compromise\n\n// If you wrote nothing, none of this investigation would exist tomorrow."
      }
    ],
    "keyTakeaways": [
      "A SOC is a 24/7 team of people, process, and technology that watches an organization's logs, turns suspicious patterns into alerts, and turns alerts into decisions.",
      "Analysts work in tiers (Tier 1 triages, Tier 2 investigates, Tier 3 responds and hunts), and the alert lifecycle is governed by SLAs and the MTTD/MTTR clock.",
      "Every triaged alert ends in one of three verdicts — benign, suspicious, or malicious — and 'suspicious' is a valid professional answer, not indecision.",
      "Run the five questions on every alert: is it normal for this entity, what fired the rule, what happened before and after, who else is affected, and what is the impact if real.",
      "The ticket is the product of your work; clear documentation with evidence and reasoning is what lets the next analyst continue and what makes your verdict defensible."
    ],
    "quiz": [
      {
        "question": "You are a SOC analyst on the morning shift. Your queue shows one Critical alert (aged 3 minutes) about ransomware behavior, two Medium alerts aged over an hour, and a Low alert aged three hours. Which do you work first and why?",
        "options": [
          {
            "label": "The Low alert, because it is the oldest and closest to breaching its SLA",
            "value": "a"
          },
          {
            "label": "The Critical ransomware alert, because severity outranks age and it poses the greatest immediate risk",
            "value": "b"
          },
          {
            "label": "The two Medium alerts, because clearing two tickets is more productive than one",
            "value": "c"
          },
          {
            "label": "Whichever alert has the shortest title, because it will be fastest to close",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "You work by priority: highest severity first, then oldest within a severity. A Critical ransomware alert poses immediate, spreading risk and must be handled before anything else. The Low alert's age does not outrank a Critical (a). Chasing ticket count over risk (c) lets a live attack run. Title length (d) has nothing to do with priority."
      },
      {
        "question": "You are a SOC analyst reviewing an alert for a login from a new country for user a.cohen. You confirm the login is real and foreign, but you have not yet checked the user's travel history or whether other accounts were touched. What is the most appropriate verdict right now?",
        "options": [
          {
            "label": "Benign, because a single foreign login is usually just travel",
            "value": "a"
          },
          {
            "label": "Malicious, because any login from a new country is always an attack",
            "value": "b"
          },
          {
            "label": "Suspicious, because the activity is unexplained and needs further investigation before you can prove it good or bad",
            "value": "c"
          },
          {
            "label": "No verdict; close the alert and move on since it is only Medium severity",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Suspicious is the correct, honest verdict when you cannot yet prove the activity is benign or malicious and further checks (travel history, scope) would resolve it. Closing as benign (a) assumes an innocent explanation you have not verified. Declaring malicious (b) overstates evidence you do not have. Closing with no verdict (d) drops a potentially real compromise."
      },
      {
        "question": "You are a SOC analyst investigating a 'Suspicious PowerShell' alert on an accountant's laptop. Applying the questioning framework, which action most directly answers 'what actually fired the rule?'",
        "options": [
          {
            "label": "Check whether the finance server was affected, to gauge business impact",
            "value": "a"
          },
          {
            "label": "Open the raw log and read the exact PowerShell command line that executed",
            "value": "b"
          },
          {
            "label": "Ask the accountant if they feel their laptop is running slowly",
            "value": "c"
          },
          {
            "label": "Immediately escalate to Tier 3 without looking at the alert details",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The alert title is never enough; you answer 'what fired the rule?' by opening the raw log and reading the exact command line that matched the detection. Checking the finance server (a) answers the impact question, not what fired the rule. A user's subjective feeling (c) is not the detection evidence. Escalating blind (d) skips the analysis entirely and hands Tier 3 no context."
      },
      {
        "question": "You are a SOC analyst who has confirmed an account compromise and need to escalate to Tier 2. Which handoff will let Tier 2 act fastest and reflects why 'the ticket is the product'?",
        "options": [
          {
            "label": "A message saying 'a.cohen looks compromised, please handle'",
            "value": "a"
          },
          {
            "label": "A ticket stating the alert, the logs and IPs you checked, the brute-force evidence, the multi-user scope, your malicious verdict, and your recommended containment steps",
            "value": "b"
          },
          {
            "label": "Closing the alert as malicious and letting Tier 2 discover it on their own",
            "value": "c"
          },
          {
            "label": "Forwarding the raw alert with no notes so Tier 2 can start fresh without your bias",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A complete ticket carrying the alert, what you checked, the evidence, the scope, your verdict with reasoning, and recommended actions lets Tier 2 act in minutes instead of rebuilding context. A bare plea for help (a) forces them to redo your work. Closing it (c) removes the escalation entirely. Sending no notes (d) wastes your investigation and restarts the clock, which is the opposite of the ticket being the product."
      }
    ],
    "references": [
      "https://www.sans.org/white-papers/soc/",
      "https://learn.microsoft.com/en-us/security/operations/security-operations-analyst",
      "https://attack.mitre.org/",
      "https://csrc.nist.gov/pubs/sp/800/61/r2/final",
      "https://www.cisa.gov/topics/cyber-threats-and-advisories"
    ],
    "xp": 160,
    "estimatedMinutes": 32,
    "createdAt": "2026-07-04T00:00:00.000Z",
    "researchUsed": false
  },
  {
    "id": "local-lesson-5",
    "slug": "how-computers-and-networks-work-for-analysts",
    "title": "How Computers and Networks Actually Work: A Ground-Up Primer for SOC Analysts",
    "topic": "Networking Fundamentals",
    "difficulty": "beginner",
    "kind": "lesson",
    "intro": "Almost every alert you will ever investigate involves computers talking to each other over a network. A malware sample calls home. An attacker logs in from a strange place. Data leaves the building to somewhere it should not. If you cannot read the network story underneath these events, you are guessing. This lesson builds that ability from the ground up, assuming you know nothing, and gives you the vocabulary and the questions you need to make sense of a connection log the very first time you see one.\n\nWe will start with the most basic idea — that every device on a network has an address and every conversation happens on a numbered port — and use everyday analogies so the concepts stick. You will learn the difference between the private addresses your company uses internally and the public addresses the internet sees, and why a single laptop shows up as 10.something in one log and as a completely different public address in another. You will learn the two main ways computers send data, TCP and UDP, and what each one tells you about what is happening. You will get a plain-language tour of the network layers so that when someone says a log 'came from layer 3' or 'layer 7', you know what they mean and why it matters.\n\nBy the end, you will be able to look at a raw firewall or connection log line, identify who was talking to whom, on what port, in which direction, and how much data moved — and then ask the questions that turn those raw fields into a judgment. Is this port normal for this application? Is the destination inside the company or out on the internet? Which way is the data flowing, and does the volume make sense? These questions separate someone who merely sees a log from someone who understands it. This is the networking foundation the rest of your SOC training depends on.",
    "sections": [
      {
        "heading": "Hosts, IP Addresses, and Ports",
        "content": "Everything on a network starts with three ideas: the host, the IP address, and the port. Get these three straight and half of networking suddenly makes sense.\n\n### The host\n\nA **host** is any device connected to a network: a laptop, a phone, a server, a printer, a firewall, a cloud virtual machine. If it can send or receive data over the network, it is a host. In your logs you will often see a host identified by a name (like FIN-PC7 or DC01) and by its address. When you investigate, 'which host' is one of the first questions you answer, because a host is the thing you can isolate, inspect, and remediate.\n\n### The IP address\n\nAn **IP address** (Internet Protocol address) is the numeric address that identifies a host on a network, so that data knows where to go. The classic analogy is a **street address**. Just as a letter needs '10 King Street' to reach a house, a packet of data needs an IP address to reach a host. The most common form you will see is IPv4, written as four numbers separated by dots, each from 0 to 255 — for example 192.168.1.50 or 8.8.8.8. Every packet crossing a network carries a **source IP** (who sent it) and a **destination IP** (where it is going). Those two fields alone answer 'who was talking to whom', which is the backbone of almost every investigation.\n\n### The port\n\nIf the IP address is the street address of a building, the **port** is the apartment number inside it. A single host runs many programs at once — a web browser, an email client, file sharing — and each needs its own line of communication. Ports, numbered 0 to 65535, are how one host keeps those conversations separate. Crucially, many services live on well-known port numbers by convention, and memorizing the common ones is one of the highest-value things a new analyst can do. Web traffic uses port 80 (HTTP) and 443 (HTTPS). Remote desktop uses 3389. Windows file sharing uses 445. Secure shell uses 22. DNS uses 53. When you see a connection to a destination port, that number is your first strong hint about what kind of activity it is.\n\n### Putting them together\n\nA network conversation is defined by the combination of source IP, source port, destination IP, and destination port — often called a **four-tuple**. Read together they tell a small story: this host, using this temporary local port, reached out to that host on that service port. The key habit to build now is to always read the destination port and ask what service normally lives there. A workstation connecting out to port 443 is ordinary web browsing. The same workstation connecting to another workstation on port 3389 (remote desktop) is far more unusual and worth a second look. The number is not proof of anything by itself, but it is the first question you ask, every time.",
        "codeExample": "// The building analogy for a network connection\n//\n//   IP ADDRESS  =  the street address of the building (which host)\n//   PORT        =  the apartment number inside it (which service)\n//\n// A connection is a four-tuple:\n//   source IP : source port  ->  destination IP : destination port\n//   192.168.1.50 : 51244     ->  93.184.216.34 : 443   (this PC browsing a website)\n\n// Common well-known destination ports every analyst should recognize:\n//   20 / 21  FTP (file transfer)      53   DNS (name lookup)\n//   22       SSH (secure remote shell) 80   HTTP  (web, unencrypted)\n//   25       SMTP (email sending)      443  HTTPS (web, encrypted)\n//   88       Kerberos (Windows auth)   445  SMB (Windows file sharing)\n//   389/636  LDAP / LDAPS (directory)  3389 RDP (remote desktop)\n\n// First question on ANY connection: what service normally lives on that dest port?"
      },
      {
        "heading": "Public vs Private IP, NAT, and Why It Shows Up in Your Logs",
        "content": "One of the first things that confuses new analysts is seeing the same laptop appear with two totally different IP addresses in two different logs. The explanation is the difference between private and public addressing, and a mechanism called NAT. Understanding this will save you hours of confusion.\n\n### Private IP addresses\n\nThe designers of the internet reserved certain address ranges for use inside private networks — homes, offices, data centers. These are the **RFC 1918** ranges, and you will see them constantly: **10.0.0.0 to 10.255.255.255**, **172.16.0.0 to 172.31.255.255**, and **192.168.0.0 to 192.168.255.255**. These addresses are not unique in the world; millions of networks use 192.168.1.1 at the same time. That is fine, because private addresses are only meaningful inside their own network — like an internal office extension number that only works within the building. When you see a 10.x, 172.16-31.x, or 192.168.x address in a log, you are almost certainly looking at an internal host on the company network.\n\n### Public IP addresses\n\nA **public IP address** is globally unique and routable across the internet. Websites, cloud services, and the company's own internet-facing edge all have public IPs. When your laptop talks to google.com, the destination is a public IP. Learning to glance at an address and instantly classify it as private (internal) or public (external) is a core reflex, because 'internal or external?' is one of the questions you ask on every connection.\n\n### NAT: why one host has two faces\n\nHere is the twist. Your office might have a thousand devices, all with private 10.x addresses, but only a handful of public IP addresses to share. **NAT** (Network Address Translation) is the mechanism, usually running on the firewall or router, that translates a private internal address into a shared public one on the way out to the internet, and translates the replies back. Think of it like a hotel switchboard: every room has an internal extension, but calls to the outside world all show the hotel's single public phone number, and the switchboard remembers which room to route the answer back to.\n\nThis is exactly why the same laptop shows as 10.4.2.15 in your internal EDR or DNS logs but as, say, 203.0.113.7 in a log recorded out on the internet or at the firewall's external interface. Nothing is wrong — you are just seeing the connection before and after translation. In good firewall logs you will often see BOTH: the original internal source and the translated external source side by side (fields named things like src and xlatesrc). The analyst lesson is critical: when you correlate an external-facing log with an internal one, you must account for NAT, or you will fail to connect a public IP back to the actual internal host that generated the traffic. Always ask: is this address pre-NAT or post-NAT, and which real host does it map to?",
        "codeExample": "// Private (RFC 1918) address cheat sheet - memorize these ranges\n//\n//   10.0.0.0     - 10.255.255.255    (a huge /8 block, common in enterprises)\n//   172.16.0.0   - 172.31.255.255    (the /12 block - note: only .16 to .31)\n//   192.168.0.0  - 192.168.255.255   (the /16 block, common in homes/small nets)\n//\n// Anything outside these ranges (e.g. 8.8.8.8, 93.184.216.34) is PUBLIC / external.\n\n// NAT in action - the SAME laptop, two faces:\n//   Internal DNS log:   src=10.4.2.15   ->  querying an internal resolver\n//   Firewall log:       src=10.4.2.15  xlatesrc=203.0.113.7  -> out to internet\n//   External web log:   client=203.0.113.7  (the internal 10.x is invisible here)\n//\n// Analyst rule: to trace a public IP back to a person, find the NAT/firewall log\n// that shows BOTH the private src and the translated public xlatesrc at that time."
      },
      {
        "heading": "TCP vs UDP and the Life of a Connection",
        "content": "When two hosts exchange data, they use one of two main transport methods: TCP or UDP. Knowing which one an event used, and how each behaves, lets you infer a surprising amount about what happened.\n\n### TCP: the reliable phone call\n\n**TCP** (Transmission Control Protocol) is connection-oriented and reliable. Before any data is sent, the two hosts establish a connection through a **three-way handshake**: the client sends a SYN ('can we talk?'), the server replies SYN-ACK ('yes, can you hear me?'), and the client sends ACK ('yes, let's go'). Only then does data flow. TCP tracks every piece, re-sends anything lost, and puts everything back in order. The analogy is a **phone call**: you dial, the other person picks up, you both confirm you can hear each other, and then you have a continuous, ordered conversation. Because TCP is reliable and ordered, it carries most of what matters: web (HTTP/HTTPS), email, file sharing, remote desktop, database traffic. When you see an established TCP session in a log, you know a real two-way conversation actually took place.\n\n### UDP: the fire-and-forget postcard\n\n**UDP** (User Datagram Protocol) is connectionless. There is no handshake and no guarantee of delivery or order — a host simply sends a packet and hopes it arrives. The analogy is dropping a **postcard in the mail**: no confirmation, no ongoing call, just a message sent off. UDP trades reliability for speed and low overhead, which is why it is used for DNS lookups, DHCP, streaming, VoIP, and many logging protocols. It is also favored by some malware for lightweight beaconing, precisely because it is cheap and stateless.\n\n### What the analyst infers\n\nThe transport tells you what kind of evidence you have. A completed TCP handshake means the two hosts genuinely connected — that is meaningful. By contrast, seeing SYN packets with no matching SYN-ACK is the classic signature of a **port scan**: someone knocking on many doors to see which open, without ever completing a call. A flood of RST (reset) packets can mean connections are being refused or torn down. On the UDP side, because there is no handshake, a single UDP packet to a port does not prove anyone was listening — so you weigh it differently. A burst of UDP to port 53 might be normal DNS, or it might be something tunneling data through DNS; the transport alone does not decide, but it shapes the questions you ask.\n\nSo when you read a connection log, note the transport (often a field like proto=tcp or proto=udp) and ask: did a real connection get established, or is this just an attempt? Is this transport normal for the service on that port — DNS on UDP/53 is expected, DNS on TCP/53 with a large payload is worth a look? The transport is a small field with a large amount of meaning packed into it.",
        "codeExample": "// TCP three-way handshake - a real connection is established\n//   client  --SYN-->      server    // \"can we talk?\"\n//   client  <--SYN-ACK--  server    // \"yes, can you hear me?\"\n//   client  --ACK-->      server    // \"yes - go\"   ==> DATA now flows\n//\n// TCP = phone call: dial, confirm, ordered two-way conversation, reliable.\n// UDP = postcard:   send and hope. No handshake, no guarantee, low overhead.\n\n// What analysts read from TCP flags in logs:\n//   many SYN, no SYN-ACK back   -> PORT SCAN (knocking on doors, no real call)\n//   burst of RST                -> connections refused / torn down\n//   full handshake + data       -> a genuine session actually happened\n\n// Typical transport by service:\n//   TCP: 80/443 web, 445 SMB, 3389 RDP, 22 SSH, 25 SMTP, database ports\n//   UDP: 53 DNS, 67/68 DHCP, 123 NTP, VoIP/streaming\n// Ask: is this transport NORMAL for that port and service?"
      },
      {
        "heading": "The Network Layers in Plain Language",
        "content": "People in security constantly refer to 'layers' — layer 3, layer 4, layer 7. This comes from a model that splits networking into stacked levels, each responsible for one job. You do not need to memorize academic theory, but you do need a working feel for the layers, because it tells you which layer a given log came from and therefore what that log can and cannot tell you.\n\n### The four practical layers\n\nThe TCP/IP model most analysts use has four layers. The **Link layer** (sometimes called layer 2) handles the physical local network — Ethernet, Wi-Fi, and the hardware MAC addresses of devices on the same local segment. The **Internet layer** (layer 3) handles IP addresses and routing between networks; this is where source IP and destination IP live. The **Transport layer** (layer 4) handles TCP and UDP and the port numbers — the reliability and the apartment-number addressing we just covered. The **Application layer** (layer 7) is the top, where the actual services live: HTTP, DNS, SMB, email, and everything a user recognizes. A handy way to remember it: the lower layers move the envelope; the top layer is the letter inside.\n\n### Which layer did this log come from?\n\nThis is the practical payoff. Different security tools observe different layers, so knowing the layer tells you the log's depth. A basic firewall or a NetFlow record is largely a **layer 3/4** view: it sees source and destination IPs, ports, protocol, and byte counts, but it does NOT see inside the conversation. It can tell you host A talked to host B on port 443 and moved 2 megabytes — but not what web page was requested. A tool that does **deep packet inspection** or an application-aware sensor like Zeek, or a web proxy, reaches **layer 7**: it can see the actual domain requested, the URL, the DNS query name, the SMB filename. An EDR on the host sees layer 7 context plus which process opened the connection.\n\n### Why this matters for your questions\n\nWhen an alert is thin, ask which layer produced it and whether a deeper-layer source exists. If your firewall log (layer 3/4) shows a suspicious connection to a public IP on port 443 but cannot tell you the domain, you pivot to a layer 7 source — the proxy or DNS logs — to learn WHERE it was really going. Conversely, if you only have a DNS log (layer 7, showing the queried name) you might pivot down to firewall flow data (layer 3/4) to learn how much data actually moved. Understanding layers keeps you from demanding information a given log physically cannot contain, and points you to the right place to get it. The layer is not trivia; it is a map of which questions each data source can answer.",
        "codeExample": "// The TCP/IP layers - what each one carries and which logs see it\n//\n// LAYER 7  Application   HTTP, DNS, SMB, email    <- the \"letter\": domains, URLs,\n//                        filenames, query names       seen by proxy, Zeek, EDR, DNS logs\n// LAYER 4  Transport     TCP / UDP + PORT numbers  <- reliability + apartment number\n//                                                     seen by firewall, NetFlow\n// LAYER 3  Internet      IP addresses + routing    <- source/dest IP, the street address\n//                                                     seen by firewall, NetFlow, router\n// LAYER 2  Link          Ethernet/Wi-Fi + MAC      <- the local segment, switch/AP logs\n//\n// Same event, two depths:\n//   Firewall (L3/L4): 10.4.2.15 -> 93.184.216.34 : 443, 2 MB out   // WHO + how much\n//   Proxy    (L7):    10.4.2.15 -> https://files.example.ru/upload  // WHERE, exactly\n//\n// Ask: which layer is this log, and is there a deeper-layer source to pivot to?"
      },
      {
        "heading": "Reading a Connection Log: What to Look At and What to Ask",
        "content": "Now we put it all together on a real artifact: a firewall connection log line. This is the kind of record you will read thousands of times, so let us walk it field by field and, more importantly, attach a question to each field. Reading a log is not about admiring the fields — it is about interrogating them.\n\n### The fields that matter\n\nA typical connection log gives you a **timestamp** (when), a **source IP and source port** (who initiated), a **destination IP and destination port** (who they reached and on what service), the **protocol** (tcp or udp), an **action** (allow or deny), and **byte counts** in each direction (how much data moved out versus in). Better logs add the application, the user, the host name, and — as we learned — NAT-translated addresses. Every one of these fields is a question waiting to be asked.\n\n### The questions, field by field\n\nStart with the **destination port**: is this port normal for this application and this host? A finance workstation reaching out on 443 is routine; the same workstation accepting inbound connections on 3389 is not. Next, classify the **destination IP** using the RFC 1918 ranges: is this internal (10.x, 172.16-31.x, 192.168.x) or a public, external address? Internal-to-internal and internal-to-external tell very different stories. Then read the **direction and byte counts**: which way is the data flowing, and does the volume make sense? Normal web browsing pulls far more data IN than it sends OUT. A workstation sending hundreds of megabytes OUT to an unfamiliar external IP is a classic exfiltration shape, even on port 443. Check the **action**: was it allowed or denied? A denied connection still tells you something tried to happen. Look at the **protocol** and ask whether it fits the port. And always widen out: **who is the source, is this normal for that host, and what else did it do around the same time?**\n\n### From fields to a verdict\n\nThe skill is chaining these questions into a judgment. Suppose you see: internal host 10.4.2.15, connecting out to public IP 185.220.101.4 on port 443, tcp, allowed, with 480 MB sent OUT and 2 KB received IN. Field by field: the port looks like normal web at first glance (question raised: but the byte direction is inverted); the destination is external and unfamiliar (question: what is this IP's reputation?); the direction is overwhelmingly outbound (question: why is a workstation uploading half a gigabyte?); the volume is large for a single session. Individually each field is innocent; together they paint a picture of possible data exfiltration disguised as HTTPS. That is the whole job in miniature — no single field convicts, but the combination, read with the right questions, produces a verdict of at least 'suspicious' and a next step of pivoting to a layer 7 source to see where 185.220.101.4 really is. Read every connection log this way: not as a row of values, but as a set of questions whose combined answers tell you whether to close, dig, or escalate.",
        "codeExample": "// An annotated firewall / connection log line - read it as QUESTIONS\n//\n// 2026-07-04T14:22:07  proto=tcp  action=allow\n//   src=10.4.2.15  spt=51244   dst=185.220.101.4  dpt=443\n//   bytes_out=503316480  bytes_in=2048  app=ssl  user=a.cohen  host=FIN-PC7\n//\n//   dst port 443?    -> normally web... but check the byte direction below\n//   dst 185.220.101.4? -> NOT RFC1918 => EXTERNAL. Reputation of this IP?\n//   direction?       -> 480 MB OUT vs 2 KB IN => inverted. Web pulls IN, not OUT\n//   volume?          -> ~480 MB in one session from a workstation => large\n//   action=allow     -> it succeeded; data actually left\n//   host/user?       -> FIN-PC7 / a.cohen has access to finance data => impact\n//\n// Combined read: possible data EXFILTRATION over HTTPS. Verdict: suspicious+.\n// Next: pivot to proxy/DNS (layer 7) to resolve where 185.220.101.4 leads,\n//       and check what FIN-PC7 did in the 30 min before this connection."
      }
    ],
    "keyTakeaways": [
      "A host has an IP address (its street address) and communicates through ports (apartment numbers); a connection is the four-tuple of source IP/port and destination IP/port.",
      "Private RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x) mean internal hosts, public IPs mean external, and NAT is why one laptop appears as a private address internally and a translated public address externally.",
      "TCP is a reliable, handshake-based 'phone call' that proves a real connection happened, while UDP is a 'fire-and-forget postcard'; SYN-without-SYN-ACK is the signature of a port scan.",
      "Logs come from different network layers — firewalls and NetFlow see layer 3/4 (IPs, ports, bytes), while proxies, DNS logs, Zeek, and EDR see layer 7 (domains, URLs, filenames) — so the layer tells you what a log can and cannot answer.",
      "Read every connection log as a set of questions: is this port normal for the app, is the destination internal or external, which direction and volume is the data, and is this normal for this host?"
    ],
    "quiz": [
      {
        "question": "You are a SOC analyst and you see a connection in a log with destination IP 10.7.3.20 and another with destination IP 203.0.113.55. What can you immediately conclude about where each connection is going?",
        "options": [
          {
            "label": "Both are external internet addresses because they are IPv4",
            "value": "a"
          },
          {
            "label": "10.7.3.20 is an internal (private RFC 1918) host and 203.0.113.55 is an external (public) address",
            "value": "b"
          },
          {
            "label": "10.7.3.20 is external and 203.0.113.55 is internal",
            "value": "c"
          },
          {
            "label": "Neither can be classified without first resolving them to hostnames",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "10.x falls in the RFC 1918 private range, so 10.7.3.20 is an internal host, while 203.0.113.55 is outside all private ranges and is therefore a public, external address. Both being external (a) ignores that 10.x is private. Reversing them (c) is simply wrong. You can classify by range without DNS resolution (d); the ranges themselves tell you internal vs external."
      },
      {
        "question": "You are a SOC analyst tracing malicious activity. An external web server's log shows the attacker connected from public IP 203.0.113.7, but your internal EDR only shows private 10.x addresses. Why might a single laptop appear under both, and how do you link them?",
        "options": [
          {
            "label": "The laptop was reassigned a new IP; there is no way to link the two",
            "value": "a"
          },
          {
            "label": "NAT translated the laptop's private address to a shared public one; find the firewall/NAT log showing both src and xlatesrc at that time to link them",
            "value": "b"
          },
          {
            "label": "The two logs refer to completely different devices and cannot be related",
            "value": "c"
          },
          {
            "label": "The public IP is the internal one; RFC 1918 ranges include 203.0.113.0",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "NAT translates many private internal addresses to a shared public IP on the way out, so the same laptop is 10.x internally and 203.0.113.7 externally; the NAT/firewall log that records both the private src and translated xlatesrc at that timestamp is how you link them. There is a reliable way to link them (a is wrong). They are the same device before and after translation (c is wrong). 203.0.113.0 is public, not RFC 1918 (d is wrong)."
      },
      {
        "question": "You are a SOC analyst reviewing traffic and you notice one host sending many TCP SYN packets to hundreds of different destination ports, with almost no SYN-ACK responses. What does this pattern most likely indicate?",
        "options": [
          {
            "label": "Normal encrypted web browsing, since HTTPS uses TCP",
            "value": "a"
          },
          {
            "label": "A port scan, because unanswered SYN packets mean the host is knocking on many doors without completing real connections",
            "value": "b"
          },
          {
            "label": "A completed file transfer, because SYN packets carry the file data",
            "value": "c"
          },
          {
            "label": "A UDP DNS flood, since DNS relies on the three-way handshake",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Many SYN packets to many ports with no SYN-ACK replies is the classic signature of a port scan: the host is probing which ports are open without ever completing the three-way handshake. Normal browsing (a) completes handshakes and targets few ports. SYN packets initiate connections and do not carry file data (c). DNS uses UDP and does not use a TCP handshake, so (d) is contradictory."
      },
      {
        "question": "You are a SOC analyst and your firewall log (a layer 3/4 source) shows an internal host connecting to a suspicious external IP on port 443, but it cannot tell you which website or domain was requested. What is the correct next step?",
        "options": [
          {
            "label": "Conclude nothing malicious happened, since the firewall did not flag a domain",
            "value": "a"
          },
          {
            "label": "Demand the firewall show the URL, since all firewall logs contain layer 7 detail",
            "value": "b"
          },
          {
            "label": "Pivot to a layer 7 source such as the web proxy or DNS logs to learn the actual domain or URL behind that IP",
            "value": "c"
          },
          {
            "label": "Ignore the connection because port 443 is always safe",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "A layer 3/4 firewall log sees IPs, ports, and bytes but not the domain or URL, so you pivot to a layer 7 source (proxy, DNS logs, or Zeek) that can reveal where the connection was really going. Concluding it is benign (a) ignores the suspicious IP and byte context. A basic firewall physically cannot show a URL, so demanding it (b) misunderstands the layer. Port 443 is not inherently safe (d) — attackers hide C2 and exfiltration inside HTTPS."
      }
    ],
    "references": [
      "https://datatracker.ietf.org/doc/html/rfc1918",
      "https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-tcpip",
      "https://docs.zeek.org/en/master/logs/conn.html",
      "https://www.sans.org/blog/tcp-ip-and-tcpdump-pocket-reference-guide/",
      "https://csrc.nist.gov/glossary/term/network_address_translation"
    ],
    "xp": 160,
    "estimatedMinutes": 34,
    "createdAt": "2026-07-04T00:00:00.000Z",
    "researchUsed": false
  },
];
export default lessons;
