import type { RoomExperience } from "./types";

// "Operation Crown Jewels" for the "asset-context-prioritisation" room.
// Script: docs/campaign/67-asset-context-prioritisation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Thornbury Fine Foods (fictional), not the graded tasks' meridian.local records.
// Signature: Same Alert, Different Day. One rule, months apart, lands on a canteen menu display, a payroll
// server and a domain controller, and the asset decides the call (queue); then a pager rule
// that weighs severity against asset value (tune). Severity comes from the tool, priority
// comes from the business.
// Game mix: duel + rush + tune.
//
// New task order (m1 belongs with the blast radius reading, f1 reads la1 and needs to follow it,
// and the room otherwise ends on a one-number flag instead of its hardest task, o1):
// asset-r1, asset-r2, asset-q1 | asset-r3, asset-q2, asset-m1, asset-la1, asset-f1 |
// asset-r4, asset-q3, asset-r5, asset-ac1 | asset-r6, asset-r7 | asset-o1
//
// Lab data differs from the graded tasks: the repeated alert is a scheduled task (4698), never a
// failed logon burst (r1, la1, ac1); the low-value host is a wall menu display, and the recovery idea sits
// on a disaster-recovery replica, never a backup server (q1); the virtualisation
// host has 22 guests, never 40 (q2); the duel asks for the first-hour move, while the graded
// matching asks for the reason (m1); the burst is 6 accounts on a planning file server from a QA
// PC, and one of them worked, never 14 on DC02 from a workstation (la1, f1); the flaw is CVSS 8.1
// on four Thornbury servers, never 9.8 on a portal and a reporting server (q3); the verdict drills
// are a restore test, a pen test out of scope, a filename match and a rollout, never logons on a
// detonation VM (ac1); the unknown host is a VM, and the business event is a product recall, never
// a launch on a payment system (r5, r7); the ranking drill has six alerts with a Medium on top and
// two Criticals at the bottom, never the graded five or their severity pattern (o1).

export const ASSET_CONTEXT_PRIORITISATION: RoomExperience = {
  roomId: "asset-context-prioritisation",
  codename: "Operation Crown Jewels",
  theme: "crownjewels",
  handler: { name: "Jonas Mbeki", role: "SOC Manager, Thornbury Fine Foods" },
  briefing: [
    "Thornbury Fine Foods. Biscuits, preserves and Christmas hampers, made by 640 people since 1894, and the next 19 days pay for the whole year.",
    "At 03:10 this morning the on-call pager woke someone for a Critical on a demo VM nobody uses.",
    "At 02:47, the same night, a Medium on the domain controller went into the queue and sat there until breakfast.",
    "Jonas Mbeki has a list of what keeps this company alive, and a product that has never read it. Learn what sits behind each alert, and put the queue in the order the business needs.",
  ],
  mission: "Read the asset behind one repeated alert, name what makes a system matter, map what each takeover reaches, find out whether a burst worked, weigh exposure and business context, chase a host nobody owns, set the on-call pager, then rank the queue.",
  estimate: "~45 min",
  look: { primary: "#f4c95d", secondary: "#b79cff", warn: "#ff6b6b" },
  scene: "facilitycrownjewels",
  layout: "facility",
  stations: [
    {
      id: "register",
      label: "The Asset Register",
      topic: "One log line, three responses · what it holds · what it controls · who uses it · exposure",
      tagline: "Same alert. What's behind the door?",
      building: "archive",
      taskIds: ["asset-r1", "asset-r2", "asset-q1"],
    },
    {
      id: "blastmap",
      label: "The Blast Map",
      topic: "Blast radius · domain controllers, hypervisors, backups, jump hosts, CI/CD · reading a burst against its target",
      tagline: "Take this box. Then what?",
      building: "control",
      taskIds: ["asset-r3", "asset-q2", "asset-m1", "asset-la1", "asset-f1"],
    },
    {
      id: "priority",
      label: "Severity or Priority",
      topic: "Internet-facing, internal-only, segmented · what CVSS can't see · business context · closing with evidence",
      tagline: "The tool scored it. Who ranks it?",
      building: "office",
      taskIds: ["asset-r4", "asset-q3", "asset-r5", "asset-ac1"],
    },
    {
      id: "pager",
      label: "The Night Pager",
      topic: "The CMDB problem · chasing an unknown host · severity, criticality and confidence · writing down why",
      tagline: "Who gets woken, and for what",
      building: "emergency",
      taskIds: ["asset-r6", "asset-r7"],
    },
    {
      id: "crownjewels",
      label: "Crown Jewels",
      topic: "Ranking concurrent alerts by more than the label",
      tagline: "All at once. Your order.",
      building: "vault",
      taskIds: ["asset-o1"],
      boss: true,
    },
  ],
  personas: {
    "asset-q1": { name: "Jonas Mbeki", role: "SOC Manager", line: "Two detections, same score, same second. Tell me how you read them." },
    "asset-q2": { name: "Jonas Mbeki", role: "SOC Manager", line: "Walk me through what that takeover means." },
    "asset-m1": { name: "Jonas Mbeki", role: "SOC Manager", line: "The board wants the blast map explained, box by box." },
    "asset-la1": { name: "Jonas Mbeki", role: "SOC Manager", line: "Read the record before anyone picks up a phone." },
    "asset-f1": { name: "Jonas Mbeki", role: "SOC Manager", line: "I need the number for the ticket." },
    "asset-q3": { name: "Jonas Mbeki", role: "SOC Manager", line: "The patch team is asking about those two servers." },
    "asset-ac1": { name: "Jonas Mbeki", role: "SOC Manager", line: "Same rule, new host. What goes on the ticket?" },
    "asset-o1": { name: "Jonas Mbeki", role: "SOC Manager", line: "One analyst, a full queue, and the whole company watching. Your order." },
  },
  briefings: {
    // ── Reading 1: the same alert, three assets ──
    "asset-r1": [
      {
        kind: "queue",
        title: "Same Alert, Different Day",
        prompt: "Wednesday, 08:30. Jonas pulled three hits on one rule from this year's tickets: same rule, same Medium from the product, months apart, and no task or script in common. Work each one as if it had just landed: read the register note under the fields, and take the call that asset deserves.",
        console: "SIEM · Incident review · Thornbury Fine Foods",
        actions: [
          { id: "log", label: "Log it, re-image at the next window", tone: "close" },
          { id: "work", label: "Work it now, call the owner", tone: "contain" },
          { id: "wake", label: "Escalate now, wake the on-call", tone: "escalate" },
        ],
        alerts: [
          {
            id: "display",
            time: "Jun 11 10:14",
            severity: "Medium",
            rule: "Scheduled task runs a script from ProgramData",
            entity: "TF-CANTEEN-D2",
            fields: [
              { k: "EventCode", v: "4698" },
              { k: "Computer", v: "TF-CANTEEN-D2.thornbury.example" },
              { k: "SubjectUserName", v: "TF-CANTEEN-D2$" },
              { k: "TaskName", v: "\\MenuRefresh" },
              { k: "TaskContent", v: "<Command>powershell.exe</Command><Arguments>-ep bypass -File C:\\ProgramData\\mf\\refresh.ps1</Arguments>" },
              { k: "dest_category", v: "display" },
              { k: "dest_bunit", v: "Catering" },
            ],
            context: "Register note: menu display on a wall in the staff canteen. Shows a local file. One local account, not joined to the domain, own VLAN with a route to the menu feed, plus one-way log forwarding, and nothing else.",
            answer: "log",
            why: "Nothing behind this door: no data, no domain trust, nowhere to go. A log entry and a rebuild is a real answer. Paging for this is how a team learns to ignore the pager.",
          },
          {
            id: "payroll",
            time: "Sep 22 15:02",
            severity: "Medium",
            rule: "Scheduled task runs a script from ProgramData",
            entity: "TF-PAY-SRV1",
            fields: [
              { k: "EventCode", v: "4698" },
              { k: "Computer", v: "TF-PAY-SRV1.thornbury.example" },
              { k: "SubjectUserName", v: "TF-PAY-SRV1$" },
              { k: "TaskName", v: "\\ReportExport" },
              { k: "TaskContent", v: "<Command>powershell.exe</Command><Arguments>-ep bypass -File C:\\ProgramData\\rx\\export.ps1</Arguments>" },
              { k: "dest_category", v: "server" },
              { k: "dest_bunit", v: "Finance" },
            ],
            context: "Register note: payroll server. Salaries and bank details for all 640 staff. Domain member, internal only, used by two people in Finance. Your shift is on, and so is its owner.",
            answer: "work",
            why: "Real data sits here, so this gets a real look today: ask the Finance owner whether anything was planned, read what the script does, watch for the next step. It stays with you for now because the worst case is this server's data, not every system in the company. If the owner can't explain it, it goes up.",
          },
          {
            id: "dc",
            time: "Nov 04 02:47",
            severity: "Medium",
            rule: "Scheduled task runs a script from ProgramData",
            entity: "TF-DC01",
            fields: [
              { k: "EventCode", v: "4698" },
              { k: "Computer", v: "TF-DC01.thornbury.example" },
              { k: "SubjectUserName", v: "TF-DC01$" },
              { k: "TaskName", v: "\\CacheSync" },
              { k: "TaskContent", v: "<Command>powershell.exe</Command><Arguments>-ep bypass -File C:\\ProgramData\\cs\\sync.ps1</Arguments>" },
              { k: "dest_category", v: "server" },
              { k: "dest_bunit", v: "IT" },
            ],
            context: "Register note: domain controller. Holds few files of its own. Signs in every account at Thornbury, so every server, laptop and service trusts what it says.",
            answer: "wake",
            why: "This one sat until breakfast because the product said Medium, and the product scored the rule without knowing what this machine is. It isn't a computer that happened to get a task: every other system trusts it. Code nobody planned on identity infrastructure is a whole-company problem until someone proves otherwise.",
          },
        ],
      },
    ],
    // ── Reading 2: what makes an asset critical ──
    "asset-r2": [
      {
        kind: "sort",
        title: "Which Question Makes It Matter?",
        prompt: "Half of Thornbury's register says 'High' with no reason beside it. Jonas wants the reason. Sort each row by the question that makes that asset matter most.",
        buckets: [
          { id: "holds", label: "What it holds" },
          { id: "controls", label: "What it controls" },
          { id: "who", label: "Who uses it" },
          { id: "exposed", label: "Whether it's exposed" },
        ],
        items: [
          { id: "recipes", text: "Recipe share: every formulation since 1894", bucket: "holds", why: "Its value is the data itself. Trade secrets make it a target even though it commands nothing." },
          { id: "customers", text: "Hamper customer database: 410,000 home addresses and orders", bucket: "holds", why: "PII, personally identifiable information. The first register question is whether anything here is worth stealing, and here it is." },
          { id: "ca", text: "Certificate server: issues the certificates every internal site is trusted by", bucket: "controls", why: "It stores very little. It matters because whatever it signs gets believed, which is a door-key kind of value, not a filing-cabinet kind." },
          { id: "bms", text: "Building management server: cold store temperatures and door locks", bucket: "controls", why: "No sensitive files at all, and it can spoil a season's stock or open every door. Beginners underweight this question." },
          { id: "dr", text: "Disaster recovery replica: sits idle, and brings the ERP back if the main site is lost", bucket: "controls", why: "Easy to file under 'holds', but nobody wants its copy for itself. What it controls is your ability to come back at all, and that stops being a quiet detail the moment something destroys the main copy." },
          { id: "fd", text: "Finance Director's laptop: same model as 300 others, signed in with supplier payment approval", bucket: "who", why: "The hardware is ordinary. An attacker who rides along with that account gets what that account can do." },
          { id: "svc", text: "svc_erp: a service account that can read every ERP (enterprise resource planning) table", bucket: "who", why: "No human behind it, and the account still carries the criticality. Ask who, or what, is signed in." },
          { id: "supplier", text: "Supplier portal: one web server, open to the internet on 443, no VPN", bucket: "exposed", why: "Anyone anywhere can try it with no foothold. That widens who can attack it, whatever it holds." },
          { id: "webmail", text: "Old webmail page, still published at a public address", bucket: "exposed", why: "Nobody uses it much, and it's still reachable by everyone. Exposure doesn't care how popular a system is." },
        ],
      },
    ],
    // ── Reading 3: blast radius ──
    "asset-r3": [
      {
        kind: "duel",
        title: "What Does It Reach?",
        prompt: "Jonas is drawing the blast map for the board. Each round, picture the intruder holding one more Thornbury system. Play the first-hour move that fits what that system reaches. A played card is gone, and two of your cards fit nothing here.",
        attacker: "The intruder",
        moves: [
          { id: "m1", move: "Holds TF-DC01", detail: "The domain controller runs the KDC, the Kerberos Key Distribution Center, which issues every sign-in ticket in the domain.", counter: "domain", hint: "How many accounts can this box vouch for?", why: "Control of the KDC lets the intruder pose as any user, domain admins included, on anything that trusts the domain. Cleaning one host fixes none of that, so the reset has to be domain-wide." },
          { id: "m2", move: "Holds TF-VH02, the virtualisation host", detail: "It runs 22 guest machines, the ERP database among them. Each guest has its own healthy endpoint agent.", counter: "guests", hint: "Where does the hypervisor sit compared with those agents?", why: "A hypervisor sits below each guest's operating system and security tools. That makes it a force multiplier: the ERP database and every other guest are in play together, and a clean report from an agent inside a guest proves nothing." },
          { id: "m3", move: "Holds TF-BKP01 and starts expiring restore points", detail: "There's nothing on it anyone wants to sell. It's what Thornbury would rebuild from.", counter: "restore", hint: "What does tomorrow's plan depend on?", why: "Nobody steals from this box, and everybody needs it the day files get encrypted. Once ransomware is in play the question is 'can we still restore at all', so that gets proved before anything else is decided." },
          { id: "m4", move: "Holds TF-JUMP01", detail: "The one trusted hop admins use to reach the factory network. Every other route into it is blocked.", counter: "sessions", hint: "What was the blocking meant to protect?", why: "Compromising the trusted hop steps around the segmentation altogether. Its blast radius is everything behind it, so you look at what it opened, not just at the box." },
          { id: "m5", move: "Holds TF-BUILD01", detail: "The CI/CD (continuous integration and deployment) server for the web shop. Production installs what it builds, automatically.", counter: "freeze", hint: "Who trusts this machine's output?", why: "Everything downstream trusts the build output, so a pipeline can carry malicious code into systems that never had an incident of their own. That's a supply-chain scale problem from one server." },
          { id: "m6", move: "Holds TF-DEMO-03", detail: "The sales team's demo VM. Its own VLAN, no domain trust, no production data, a copy of a brochure site.", counter: "note", hint: "What's on the far side of this one?", why: "A full compromise that reaches nothing. Spending a domain-wide response here is the same mistake as under-reacting on TF-DC01: the response didn't look at the asset." },
        ],
        cards: [
          { id: "edge", name: "Block the source at the edge", effect: "One firewall rule on the internet perimeter." },
          { id: "guests", name: "Distrust every guest", effect: "Check them all from outside, at the hypervisor layer." },
          { id: "note", name: "Log it and rebuild", effect: "A note on the ticket, a fresh image." },
          { id: "domain", name: "Domain-wide credential reset", effect: "Privileged accounts, and krbtgt twice." },
          { id: "freeze", name: "Freeze the pipeline", effect: "Stop deployments, audit what already shipped." },
          { id: "onepass", name: "Reset one password", effect: "The account that was signed in." },
          { id: "restore", name: "Prove a clean restore", effect: "Test that a good copy still comes back." },
          { id: "sessions", name: "List every onward session", effect: "Everything it opened into the zones behind it." },
        ],
        lesson: "Blast radius is one question: if this were fully taken right now, what else does the attacker get? Ask it in the first minutes, because the answer picks your first hour. Identity means a domain-wide reset, a hypervisor means every guest, backups mean proving recovery, a jump host means all it can reach, a pipeline means all it ships to, and an isolated box means a note.",
      },
    ],
    // ── Log analysis warm-up: read a burst against its target ──
    "asset-la1": [
      {
        kind: "worksheet",
        title: "Did Any of Them Work?",
        prompt: "Wednesday 14:31. The planning file server, TF-PLAN-FS1, logged a burst of failed logons. Jonas wants four answers from the Security log, not an opinion.",
        caption: "Security log · TF-PLAN-FS1 · Wed 14:31 to 14:34 · 4625 failed logon, 4624 successful logon",
        columns: ["Time", "EventCode", "TargetUserName", "LogonType", "SubStatus", "IpAddress", "WorkstationName"],
        rows: [
          ["14:31:04", "4625", "j.pereira", "3", "0xC000006A", "10.40.62.118", "TF-LAB-PC06"],
          ["14:31:19", "4625", "m.aldous", "3", "0xC000006A", "10.40.62.118", "TF-LAB-PC06"],
          ["14:31:33", "4624", "r.castellano", "3", "-", "10.40.12.30", "TF-FIN-LT22"],
          ["14:31:41", "4625", "h.nowell", "3", "0xC000006A", "10.40.62.118", "TF-LAB-PC06"],
          ["14:32:02", "4625", "p.tanaka", "3", "0xC000006A", "10.40.62.118", "TF-LAB-PC06"],
          ["14:32:18", "4625", "m.aldous", "3", "0xC000006A", "10.40.62.118", "TF-LAB-PC06"],
          ["14:32:40", "4625", "d.whitlock", "3", "0xC000006A", "10.40.62.118", "TF-LAB-PC06"],
          ["14:33:05", "4625", "c.vance", "3", "0xC000006A", "10.40.62.118", "TF-LAB-PC06"],
          ["14:33:52", "4624", "p.tanaka", "3", "-", "10.40.62.118", "TF-LAB-PC06"],
        ],
        questions: [
          { id: "count", q: "How many distinct accounts did 10.40.62.118 fail on?", hint: "Count names, not rows. One name appears twice.", answer: ["6", "six"], why: "Seven failed rows, six accounts. Many accounts from one source in a short window is the shape of password spraying, and the distinct count is the number that goes on the ticket." },
          { id: "hit", q: "Which account then logged on successfully from that same source?", hint: "Find a 4624 with the same IpAddress as the burst.", answer: ["p.tanaka", "tanaka"], why: "Always look for the success after the failures. That turns 'someone tried' into 'someone got in'. A lockout notice is only a symptom, and it may never come. Reset p.tanaka and check what the session did: don't disable every name in the burst, because some of them may be service accounts that break things." },
          { id: "edge", q: "The source is an internal QA lab PC. Would a block at the internet edge stop this? (yes/no)", hint: "Does 10.40.x.x traffic ever cross the edge?", answer: ["no"], why: "10.40.62.118 is a private, internal address, so this traffic never reaches the perimeter. You contain the source itself: isolate TF-LAB-PC06 and investigate it." },
          { id: "type", q: "LogonType 3 means a network logon. Does that tell you this server is low value? (yes/no)", hint: "Which question decides value: how the logon arrived, or what sits behind it?", answer: ["no"], why: "Type 3 is everyday traffic on any server, including domain controllers. It says how the logon arrived. The target's role sets the priority: a failed-only burst on a planning share could wait, but this one worked, so it is worked now, and the same burst on identity infrastructure goes straight up." },
        ],
      },
    ],
    // ── Reading 4: exposure ──
    "asset-r4": [
      {
        kind: "reactor",
        title: "Who Can Get There?",
        prompt: "Thursday morning, and the patch team wants Thornbury's servers grouped by reach. Route each one into the exposure level the network really gives it before it reaches the end of the belt.",
        reactors: [
          { id: "internet", label: "INTERNET-FACING", sub: "no foothold needed" },
          { id: "internal", label: "INTERNAL-ONLY", sub: "needs a way into the network" },
          { id: "segmented", label: "SEGMENTED", sub: "blocked even from other internal hosts" },
        ],
        items: [
          { id: "shop", text: "Hamper shop web server, public on 443", reactor: "internet", why: "Anyone scanning the internet can reach it right now, with no prior access." },
          { id: "edi", text: "Supplier EDI (electronic data interchange) gateway on a public IP", reactor: "internet", why: "A public address means a stranger can try it. That the expected users are suppliers doesn't narrow who else can." },
          { id: "intra", text: "HR intranet, open to any office PC", reactor: "internal", why: "Internet-wide scanning can't touch it, but one phished laptop can." },
          { id: "print", text: "Print server, any device on the office LAN can reach it", reactor: "internal", why: "Inside the network there's nothing further in the way." },
          { id: "vault", text: "Recipe share TF-RECIPE-FS1, reachable only through the jump host", reactor: "segmented", why: "Even a compromised office PC can't talk to it directly. That's what segmented means." },
          { id: "cold", text: "Cold store controllers, firewall allows one management subnet", reactor: "segmented", why: "Other internal hosts are refused by the internal firewall, so an attacker needs that subnet first." },
          { id: "paycon", text: "Payroll admin console, one management network plus a second MFA (multi-factor authentication) prompt", reactor: "segmented", why: "A network limit plus an extra login: layers an attacker has to pass even from inside." },
        ],
      },
      {
        kind: "simulate",
        title: "One Flaw, Four Doors",
        prompt: "The scanner reports the same flaw, CVSS 8.1, on four Thornbury servers. Run each one through the doors an attacker would have to pass. A green door is a door that holds.",
        checks: [
          { name: "The edge", question: "Is it blocked from the internet?" },
          { name: "The LAN", question: "Is it blocked from ordinary office PCs?" },
          { name: "Extra login", question: "Does reaching it need a further step: VPN, MFA or a jump host?" },
        ],
        scenarios: [
          { id: "web", label: "TF-WEB-01", detail: "Hamper shop web server. Register says: internet-facing.", results: ["fail", "fail", "fail"], why: ["Published on purpose.", "Reachable from anywhere, so from the office too.", "No login stands in front of the flaw."], verdict: "CVSS 8.1 and nothing in the way. Anyone scanning tonight can try it with no foothold at all, so it goes first." },
          { id: "lims", label: "TF-LIMS-01", detail: "Quality lab system (LIMS, laboratory information management system). Register says: internal-only.", results: ["fail", "fail", "fail"], why: ["A vendor's port-forward from 2024 was never removed.", "Open to the office, as expected.", "The vendor path has no extra step."], verdict: "The register says internal, the firewall says otherwise. Exposure is what the network does today, not what a form says. It joins the top of the queue." },
          { id: "intra", label: "TF-INTRA-02", detail: "HR intranet. Register says: internal-only.", results: ["pass", "fail", "fail"], why: ["No route in from the internet.", "Any office PC can reach it.", "No further step."], verdict: "The same 8.1 needs a foothold first. One phished laptop would be enough, so it follows soon after, not next quarter." },
          { id: "vault", label: "TF-RECIPE-FS1", detail: "Recipe share. Register says: segmented.", results: ["pass", "pass", "pass"], why: ["No route from the internet.", "Office PCs are refused.", "Admins come through the jump host."], verdict: "Same score, and an attacker has to breach several layers first. CVSS rates how bad the flaw is if reached. It can't see who can reach it. That's less urgent, never ignored: it still gets patched." },
        ],
      },
    ],
    // ── Reading 5: business context beats technical severity ──
    "asset-r5": [
      {
        kind: "rush",
        title: "Tool or Business?",
        prompt: "Thursday, 10:00. A labelling error on a batch of ginger preserve has just started a product recall, and facts are flying at Jonas's desk. Call each one: could the security product measure this by itself, or does only the business know it?",
        trueLabel: "The tool measures it",
        falseLabel: "Only the business knows",
        seconds: 60,
        target: 10,
        cards: [
          { id: "c1", text: "CVSS base score 8.1", answer: true, why: "Worked out from the flaw itself. No knowledge of your company needed." },
          { id: "c2", text: "The traceability server is running a live recall", answer: false, why: "Nothing in a log says 'this week the company leans on this box'." },
          { id: "c3", text: "Public exploit code exists", answer: true, why: "Exploit availability is a technical fact that products track." },
          { id: "c4", text: "Hamper dispatch starts in 19 days", answer: false, why: "A calendar fact. It changes what hurts, and no sensor sees it." },
          { id: "c5", text: "Detection confidence: 85%", answer: true, why: "The product's own measure of its own match." },
          { id: "c6", text: "This laptop's owner approves supplier payments", answer: false, why: "Whose account this is, and what it can approve, is business knowledge." },
          { id: "c7", text: "The process ran with a hidden window", answer: true, why: "Observed behaviour on the endpoint." },
          { id: "c8", text: "Nobody depends on this demo VM this week", answer: false, why: "Only people can tell you that. It's why a High there can wait." },
          { id: "c9", text: "The file hash matches known malware", answer: true, why: "A direct technical comparison." },
          { id: "c10", text: "Losing this system stops the bakery line for a day", answer: false, why: "That's an impact statement. The product has no idea what a bakery line is." },
          { id: "c11", text: "The payload was quarantined", answer: true, why: "The product's own action, recorded by the product." },
          { id: "c12", text: "The only person who can approve downtime is on leave", answer: false, why: "It changes what you can do next, and it lives in a calendar." },
          { id: "c13", text: "400 files renamed in one minute", answer: true, why: "A count of observed events, exactly what a sensor is good at." },
          { id: "c14", text: "Tag in the alert: Tier 1 asset", answer: false, why: "The trap in this deck. The SIEM displays it, but a person in the business decided it, and it's only as fresh as the register behind it." },
        ],
        lesson: "Severity is a property of the finding, built from what a product can measure: the score, the exploit, its confidence. Priority is your judgement of response order, built by folding in what only the organisation knows. Neither is wrong. A Medium on the system the business is leaning on this week can outrank a High on a box nobody needs. Use severity as an input, and never as the final word.",
      },
    ],
    // ── Analyst choice warm-up: the verdict needs evidence ──
    "asset-ac1": [
      {
        kind: "queue",
        title: "What Goes on the Ticket?",
        prompt: "Four alerts from around the business. In each one the rule saw something, and Jonas wants the verdict that belongs on the ticket. Read what really happened, then check that any paperwork covers this host at this time.",
        console: "Endpoint alerts · Verdicts",
        actions: [
          { id: "tp", label: "True positive: escalate", tone: "escalate" },
          { id: "btp", label: "Benign true positive: close, cite the ticket", tone: "close" },
          { id: "fp", label: "False positive: send to tuning", tone: "contain" },
        ],
        alerts: [
          {
            id: "restore",
            time: "Sat 03:00",
            severity: "Critical",
            rule: "Mass file rename on a file server",
            entity: "TF-RESTORE-T1",
            fields: [
              { k: "process.name", v: "restore_verify.exe" },
              { k: "threshold_result.count", v: "18400" },
              { k: "network.vlan.id", v: "902" },
              { k: "labels.change_ticket", v: "CHG-20418, approved, Sat 02:30 to 04:30, host TF-RESTORE-T1" },
            ],
            context: "IT confirms: the monthly restore test renames every file to prove the copies read back. VLAN 902 has no route to production.",
            answer: "btp",
            why: "The rule saw a real mass rename, so it did its job. The ticket names this host and this window, and IT confirms it. Close it and cite CHG-20418. Don't call it a false positive: that label says the rule misfired, and it invites someone to weaken a rule you badly want on real file servers.",
          },
          {
            id: "pentest",
            time: "Mon 11:05",
            severity: "Critical",
            rule: "LSASS memory read by an unsigned process",
            entity: "TF-QA-12",
            fields: [
              { k: "process.name", v: "tmpdbg.exe" },
              { k: "Target.process.name", v: "lsass.exe" },
              { k: "labels.change_ticket", v: "CHG-20507, approved, penetration test, TF-WEB hosts only, ended Fri 18:00" },
            ],
            context: "IT says: the testers finished on Friday, and TF-QA-12 was never in scope.",
            answer: "tp",
            why: "A ticket exists and it doesn't cover this: wrong host, wrong week. Paperwork only explains what it names. Credential theft outside the approved scope is an intrusion until proven otherwise.",
          },
          {
            id: "deck",
            time: "Tue 09:40",
            severity: "High",
            rule: "Credential theft tool on disk",
            entity: "TF-HR-LT09",
            fields: [
              { k: "file.name", v: "mimikatz_awareness_quiz.pptx" },
              { k: "process.name", v: "POWERPNT.EXE" },
              { k: "rule.description", v: "file.name contains \"mimikatz\"" },
            ],
            context: "The file is HR's security awareness slide deck. Nothing was executed apart from PowerPoint.",
            answer: "fp",
            why: "The behaviour the rule describes never happened: there's no tool, only a word in a filename. That's a real false positive, and tuning is the correct home for it.",
          },
          {
            id: "rollout",
            time: "Wed 14:20",
            severity: "High",
            rule: "Remote service installed on many hosts",
            entity: "TF-DEPLOY-01",
            fields: [
              { k: "event.code", v: "7045" },
              { k: "service.name", v: "deploy_agent" },
              { k: "threshold_result.count", v: "312" },
              { k: "user.name", v: "svc_deploy" },
              { k: "labels.change_ticket", v: "CHG-20533, approved, Wed 14:00 to 16:00, laptop rollout from TF-DEPLOY-01" },
            ],
            context: "IT confirms the rollout, the source host and the service name. This host is on the production network, not isolated.",
            answer: "btp",
            why: "It matches what attackers do, and it really happened, so it isn't false. It's also authorised, and the ticket covers this source and this hour. Isolation isn't what makes a close safe here: verified authorisation is. Close it and cite the ticket.",
          },
        ],
      },
    ],
    // ── Reading 6: the CMDB problem ──
    "asset-r6": [
      {
        kind: "trace",
        title: "The Host Nobody Owns",
        prompt: "A host called TF-TMP-4417 has no row in the asset register, or in the CMDB (configuration management database) behind it. The tempting move is to skip it and work something documented. Jonas says chase it, through records that don't depend on the register.",
        lead: "TF-TMP-4417 at 10.40.7.204 connected to the ERP database at Thu 02:12. The register has no row for it.",
        steps: [
          {
            id: "dhcp", source: "DHCP audit log · TF-DC01",
            ask: "When did this name first get an address, and from which network card?",
            columns: ["ID", "Date", "Time", "Description", "IP Address", "Host Name", "MAC Address"],
            rows: [
              ["11", "10/30/26", "08:47", "Renew", "10.40.7.88", "TF-HR-LT09.thornbury.example", "3C52A10F9B10"],
              ["11", "10/31/26", "18:12", "Renew", "10.40.7.31", "TF-SALES-LT04.thornbury.example", "D4A2B1007E31"],
              ["10", "11/01/26", "01:58", "Assign", "10.40.7.204", "TF-TMP-4417.thornbury.example", "005056A1C3E2"],
              ["11", "11/02/26", "07:02", "Renew", "10.40.7.88", "TF-HR-LT09.thornbury.example", "3C52A10F9B10"],
              ["11", "11/03/26", "01:59", "Renew", "10.40.7.204", "TF-TMP-4417.thornbury.example", "005056A1C3E2"],
              ["11", "11/05/26", "02:00", "Renew", "10.40.7.204", "TF-TMP-4417.thornbury.example", "005056A1C3E2"],
            ],
            answer: 2,
            why: "ID 10 is a new lease and ID 11 a renewal, so the first sighting is Sunday 01:58. A MAC address starting 00:50:56 is VMware's range for virtual adapters, so this is a virtual machine, not something plugged in under a desk.",
            learned: "First lease Sun 01:58. MAC 00:50:56: a virtual machine.",
          },
          {
            id: "dns", source: "DNS debug log · TF-DC01",
            ask: "Filter on 10.40.7.204. Which lookup shows it went looking for something it has no reason to know?",
            columns: ["Time", "Client", "Query", "Type"],
            rows: [
              ["11/05 02:11:40", "10.40.7.88", "tf-intra-02.thornbury.example", "A"],
              ["11/05 02:11:52", "10.40.7.204", "time.thornbury.example", "A"],
              ["11/05 02:11:58", "10.40.7.31", "tf-intra-02.thornbury.example", "A"],
              ["11/05 02:12:03", "10.40.7.204", "tf-erp-db1.thornbury.example", "A"],
              ["11/05 02:12:09", "10.40.7.88", "time.thornbury.example", "A"],
            ],
            answer: 3,
            why: "Everything asks for the time. A throwaway test box that nobody remembers has no reason to resolve the ERP database at 02:12. Silence in the register told you nothing, and this does.",
            learned: "Thu 02:12: it looked up the ERP database.",
          },
          {
            id: "vc", source: "Virtualisation platform · Events · TF-VH02",
            ask: "The MAC says it's a VM. Which event tells you who built it?",
            columns: ["Time", "Event", "User"],
            rows: [
              ["11/01 01:43", "Powered on virtual machine TF-TMP-4417", "THORNBURY\\adm-k.sorensen"],
              ["11/01 01:41", "Created virtual machine TF-TMP-4417 on TF-VH02", "THORNBURY\\adm-k.sorensen"],
              ["10/30 16:45", "Task: Remove virtual machine TF-INTRA-01", "THORNBURY\\adm-j.reese"],
              ["10/30 16:20", "Powered off virtual machine TF-INTRA-01", "THORNBURY\\adm-j.reese"],
            ],
            answer: 1,
            why: "The cloud or virtualisation console keeps its own record, and a VM can't exist without it. Created at 01:41 on a Sunday, 17 minutes before the first lease, by an admin account.",
            learned: "Built Sun 01:41 on TF-VH02 by adm-k.sorensen.",
          },
          {
            id: "ask", source: "Infrastructure team · reply to Jonas",
            ask: "You asked the people instead of trusting the silence. Which answer turns this from an unknown box into a finding?",
            columns: ["Asked", "Answer"],
            rows: [
              ["Where was the owner of adm-k.sorensen on Sunday?", "Kai Sorensen: on leave since 10/30, no remote access requested"],
              ["Is there a change ticket for a new VM this week?", "None raised"],
              ["Is there a backup policy on it?", "No"],
              ["Does it run an endpoint agent?", "No"],
            ],
            answer: 0,
            why: "No ticket could be sloppy paperwork. An admin account in use at 01:41 while its owner is on leave isn't. An attacker picks exactly the kind of box that shows up nowhere an analyst looks. Whatever it turns out to be, 'we don't know what this is' was already worth escalating.",
            learned: "Admin account used while its owner was on leave. Escalated.",
          },
        ],
      },
    ],
    // ── Reading 7: combining severity, criticality and confidence ──
    "asset-r7": [
      {
        kind: "tune",
        title: "Set the On-Call Pager",
        prompt: "Jonas's pager fires on one thing today: a product score of 70 or more, on any machine. Thornbury's register now gives each asset a value from 1 to 10. Replay the month's alerts: 'attacks' are the six worth waking someone for, and 'false' is anything that can wait for morning. Set both floors so all six page and nothing else does.",
        eventColumn: "Alert from the last month",
        dials: [
          { id: "sev", label: "Minimum product score", short: "Score", unit: "pts", min: 0, max: 100, step: 1, start: 70, dir: "above" },
          { id: "value", label: "Minimum asset value", short: "Value", unit: "/ 10", min: 1, max: 10, step: 1, start: 1, dir: "above" },
        ],
        mode: "all",
        events: [
          { id: "b1", label: "Unplanned Group Policy change on TF-DC01", bad: true, values: { sev: 58, value: 10 } },
          { id: "b2", label: "Encoded PowerShell on the ERP database server", bad: true, values: { sev: 63, value: 9 } },
          { id: "b3", label: "Ransomware canary file touched on the recipe share", bad: true, values: { sev: 91, value: 9 } },
          { id: "b4", label: "New root session on TF-VH02, no ticket", bad: true, values: { sev: 74, value: 10 } },
          { id: "b5", label: "Mass read of payroll tables outside the pay run", bad: true, values: { sev: 47, value: 8 } },
          { id: "b6", label: "Malware running, not blocked, on the Finance Director's laptop", bad: true, values: { sev: 83, value: 7 } },
          { id: "g1", label: "Exploit attempt on TF-DEMO-03, isolated", bad: false, values: { sev: 96, value: 1 } },
          { id: "g2", label: "Malware quarantined on TF-CANTEEN-D2", bad: false, values: { sev: 88, value: 1 } },
          { id: "g3", label: "Adware on a marketing laptop", bad: false, values: { sev: 61, value: 4 } },
          { id: "g4", label: "Directory sync's routine LDAP burst on TF-DC01", bad: false, values: { sev: 24, value: 10 } },
          { id: "g5", label: "Admin tool on TF-PAY-SRV1 inside a ticketed patch window", bad: false, values: { sev: 41, value: 8 } },
          { id: "g6", label: "Macro blocked on a warehouse PC", bad: false, values: { sev: 72, value: 5 } },
          { id: "g7", label: "Trojan blocked on a bakery line PC", bad: false, values: { sev: 66, value: 6 } },
        ],
        goal: { catch: 6, maxFalse: 0 },
        deploys: 3,
        lesson: "The old rule caught three of six and woke people three times for nothing, because it read one input. The value floor drops loud alerts on boxes with nowhere to go, and the score floor drops the routine hum on important ones. Neither works alone. Confidence is the third input, and these two dials can't see it: the admin tool in the patch window stayed quiet on its low score, and on a real shift it's the ticket that clears it. The whole rule is only as good as the register feeding it.",
      },
      {
        kind: "sort",
        title: "Would This Note Survive a Handover?",
        prompt: "Every time an alert ranks below its label, someone later asks why. Jonas pulled eight triage notes from this week. A good note names the asset factor and the evidence. Sort them.",
        buckets: [
          { id: "good", label: "Reviewable: factor and evidence" },
          { id: "bad", label: "Rewrite it" },
        ],
        items: [
          { id: "n1", text: "Ranked below the Medium on TF-DC01: TF-DEMO-03 sits on isolated VLAN 903, no route to production, firewall rule FW-2210.", bucket: "good", why: "Factor: isolation. Evidence: a rule anyone can look up." },
          { id: "n2", text: "Low priority, seems fine.", bucket: "bad", why: "No factor and no evidence. The next analyst learns nothing and has to start again." },
          { id: "n3", text: "Closed as benign true positive: CHG-20418 covers this host and window, confirmed by IT at 09:14.", bucket: "good", why: "A verdict, a ticket number, and who confirmed it." },
          { id: "n4", text: "Probably a test box.", bucket: "bad", why: "A guess about the asset. Who checked, and where?" },
          { id: "n5", text: "Canteen display, not important.", bucket: "bad", why: "It names the asset and skips the reason. 'Not important' is the conclusion the evidence should support." },
          { id: "n6", text: "Kept above the High queue: TF-TRACE-01 is load-bearing during recall R-118, confirmed by the Quality Manager at 10:20.", bucket: "good", why: "Business context, written down with who said so, so it can be reversed when the recall ends." },
          { id: "n7", text: "Product says Critical, but this rule is always noisy.", bucket: "bad", why: "A feeling about a rule. It doesn't say why this alert, on this asset, is safe to hold back." },
          { id: "n8", text: "Held until morning: asset value 3 in the register, reviewed 10/12, no domain trust, nothing ran.", bucket: "good", why: "Factor, source and date, so an auditor can see the decision was made on purpose." },
        ],
      },
    ],
    // ── Boss warm-up: rank a live queue on all three inputs ──
    "asset-o1": [
      {
        kind: "sequence",
        title: "Friday's Queue, in Order",
        prompt: "Friday 11:20, day two of the recall, and six alerts are open at once. Tap them from first to last. Weigh three things for each: the label, the asset behind it, and how sure you are it's real and still live.",
        items: [
          { id: "macro", text: "CRITICAL · Macro blocked on a warehouse PC, nothing ran", note: "Already stopped, on a PC that reaches a stock screen. A Critical can sit this low, as long as the note says why." },
          { id: "trace", text: "HIGH · Unexplained script on TF-TRACE-01, the batch traceability server, mid-recall", note: "Not confirmed yet, but the whole recall runs on this server this week. That lifts it over louder alerts on lesser systems." },
          { id: "restore", text: "CRITICAL · Mass file rename on TF-RESTORE-T1, still open from Saturday's restore test, ticket confirmed by IT", note: "Real, authorised and explained. Confidence that it's malicious is near zero, so the top label goes to the bottom of the list." },
          { id: "dc", text: "MEDIUM · Account added to Domain Admins on TF-DC01, no change ticket", note: "The smallest label on the screen. It's also a confirmed change, not a suspicion, and it reaches every system in the company. When two alerts both touch important systems, the one that's confirmed and reaches further goes first." },
          { id: "demo", text: "HIGH · Repeated outbound beacon from TF-DEMO-03, isolated from production, still open", note: "It can't reach production, so it waits behind anything with reach. The beacon is live and unexplained, though, so it sits above what's already contained or explained." },
          { id: "laptop", text: "HIGH · Infostealer still running on a customer service laptop, ordinary account", note: "Live and real, but it reaches one user's access. Behind the recall server, ahead of the isolated box." },
        ],
        order: ["dc", "trace", "laptop", "demo", "macro", "restore"],
        doneNote: "Read top to bottom, the labels go Medium, High, High, High, Critical, Critical, the reverse of what the product would do. Nothing in that order ignores severity: each place comes from severity, what the asset reaches and holds, what the business needs this week, and whether the threat is confirmed and still live. Where something ranks below its label, the ticket says why.",
      },
    ],
  },
};
