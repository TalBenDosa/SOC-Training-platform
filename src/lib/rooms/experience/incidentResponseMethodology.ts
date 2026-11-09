import type { RoomExperience } from "./types";

// "Operation Tabletop" for the "incident-response-methodology" room.
// Script: docs/campaign/60-incident-response-methodology.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// TASK ORDER CHANGED. The room lists r1, r2, r3, q1, q2, q3, la1, flag1, q4, q5, which puts all
// three readings first. New order, so each phase's questions follow its reading and the hardest
// task closes the room: r1, flag1 | r2, q3, q1 | r3, q4 | q2, q5 | la1.
//
// Oakhollow Water Trust (fictional water utility). Mentor: Imogen Achieng, Incident Manager.
// Signature: a live tabletop exercise. One running incident dealt as injects, and every deck
// opens on what the last decision left on the table: VPN logs kept in Preparation expose first
// access, first access picks the restore point, a memory image kept during Containment writes
// the reset list. `queue` is the exercise log, `outbreak` is containment under pressure, and the
// Run B `defuse` replays the same incident for a team that took the shortcuts.
// Game mix: defuse + duel + outbreak. Other labs: anatomy, hotspot, inspect, queue, reactor, sort.
// Lab data differs from the graded tasks: the exercise is an intruder on stolen credentials, never
// ransomware or a file share being encrypted (q1, la1); a server spreading by PsExec is what gets
// isolated, not a workstation (q1); dwell is 10 days and a clean restore point still exists,
// never 45 days against 30 of retention (q2); the disguise is spoolsv.exe in ProgramData, never
// svchost.exe in Windows\Temp, and the scope comes from a command line, not volume fields (la1).
// KRBTGT and the 24 to 72 hour review window are pure recall (q4, q5): each is shown once as a
// row with its label and no lab asks for it. No lab asks for the order of the phases.

export const INCIDENT_RESPONSE_METHODOLOGY: RoomExperience = {
  roomId: "incident-response-methodology",
  codename: "Operation Tabletop",
  theme: "tabletop",
  handler: { name: "Imogen Achieng", role: "Incident Manager, Oakhollow Water Trust" },
  briefing: [
    "Oakhollow Water Trust. Two treatment works, 210,000 people on the supply, and one day a year when nobody touches a real server.",
    "Today is that day. Imogen Achieng has cleared the boardroom, laid the network map on the table and put a deck of cards face down.",
    "Each card is one moment of an intrusion that has not happened yet. You decide, it goes on the log, and the next card starts from what you left behind.",
    "Nothing on the log can be taken back. Learn why the order of work matters while it is still only cards.",
  ],
  mission: "Tell an event from an incident, seat the response team, rate a growing incident, keep the evidence alive while you contain the spread, clear the intruder out, restart from the right point, then put the cards down for a real alert.",
  estimate: "~60 min",
  look: { primary: "#22b8cf", secondary: "#facc15", warn: "#f43f5e" },
  scene: "facilitytabletop",
  layout: "facility",
  story: {
    intro: { title: "Face Down", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-intro-71ae6c0c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-intro-d882da6a.jpg" },
    afterStation: {
      firstcall: { title: "The Clock Started", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-ch2-c795732e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-ch2-9cb4ee87.jpg" },
      clearout: { title: "The Same Night, Again", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-ch3-e68479a3.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-ch3-2f7801c9.jpg" },
      notadrill: { title: "Cards Down", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-finale-97da9c09.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/incident-response-methodology/tabletop-finale-680d4f14.jpg" },
    },
  },
  stations: [
    {
      id: "firstcall",
      label: "The First Call",
      topic: "Event, alert, incident · PICERL and NIST SP 800-61 · IR team roles and RACI",
      tagline: "Is it an incident yet?",
      building: "control",
      taskIds: ["ir-method-r1", "ir-method-flag1"],
    },
    {
      id: "spread",
      label: "Stop the Spread",
      topic: "Identification · P1 to P4 severity · evidence preservation · chain of custody · short-term and long-term containment",
      tagline: "Keep the evidence, hold the line",
      building: "lab",
      taskIds: ["ir-method-r2", "ir-method-q3", "ir-method-q1"],
    },
    {
      id: "clearout",
      label: "Clear Them Out",
      topic: "Eradication checklist · persistence · credential resets · rebuild or clean · recovery steps",
      tagline: "One file gone is not gone",
      building: "factory",
      taskIds: ["ir-method-r3", "ir-method-q4"],
    },
    {
      id: "restart",
      label: "Restart and Review",
      topic: "What shortcuts cost · clean restore points · re-infection · post-incident review",
      tagline: "Run it again, the wrong way",
      building: "office",
      taskIds: ["ir-method-q2", "ir-method-q5"],
    },
    {
      id: "notadrill",
      label: "Not a Drill",
      topic: "A live P1 alert, read field by field",
      tagline: "Cards down",
      building: "ticket",
      taskIds: ["ir-method-la1"],
      boss: true,
    },
  ],
  personas: {
    "ir-method-flag1": { name: "Imogen Achieng", role: "Incident Manager", line: "One word for the log, please." },
    "ir-method-q3": { name: "Imogen Achieng", role: "Incident Manager", line: "The scribe wants this phase in one line." },
    "ir-method-q1": { name: "Imogen Achieng", role: "Incident Manager", line: "New card, and everyone at the table is looking at you." },
    "ir-method-q4": { name: "Imogen Achieng", role: "Incident Manager", line: "One line of the sheet still needs a name. Which account goes on it?" },
    "ir-method-q2": { name: "Imogen Achieng", role: "Incident Manager", line: "Recovery is on hold until this one is answered." },
    "ir-method-q5": { name: "Imogen Achieng", role: "Incident Manager", line: "The chair wants this meeting explained before it goes in the diary." },
    "ir-method-la1": { name: "Imogen Achieng", role: "Incident Manager", line: "Cards down. That pager is not part of the exercise." },
  },
  briefings: {
    // ── Reading 1: what an incident is, the phases, the team ──
    "ir-method-r1": [
      {
        kind: "queue",
        title: "Event, Alert or Incident?",
        prompt: "Deck 1. Imogen opens the exercise with Friday night's duty log. Call each line: an event is anything that happened, an alert is a rule that matched and needs a look, and an incident is confirmed by an analyst and needs a structured response. The severity column is the tool's opinion, not yours.",
        console: "Exercise log · Duty desk",
        actions: [
          { id: "event", label: "Log it: event", tone: "close" },
          { id: "alert", label: "Investigate: alert", tone: "escalate" },
          { id: "incident", label: "Declare: incident", tone: "contain" },
        ],
        alerts: [
          {
            id: "vpnoff", time: "23:15", severity: "Low", rule: "No rule: VPN session ended", entity: "OAK-VPN-01",
            fields: [{ k: "user", v: "j.marsh" }, { k: "action", v: "session-logout" }, { k: "duration", v: "2h 41m" }],
            context: "The on-call engineer signed off after checking pump telemetry. No detection rule looked at this line.",
            answer: "event", why: "A neutral record that matched no rule and needs nothing from anyone. Most of what a network produces is this.",
          },
          {
            id: "denied", time: "00:04", severity: "Low", rule: "No rule: inbound connections denied", entity: "OAK-FW-01",
            fields: [{ k: "action", v: "deny" }, { k: "service", v: "tcp/3389" }, { k: "count", v: "3,402 in 1 hour" }, { k: "src", v: "198.51.100.0/24" }],
            context: "The firewall did its job. The internet knocks on this port every night, and no rule watches this count.",
            answer: "event", why: "A blocked connection is a log entry like any other. A big number is not a detection: no rule fired and nothing got in.",
          },
          {
            id: "fails", time: "00:41", severity: "Medium", rule: "Multiple failed sign-ins", entity: "p.khan",
            fields: [{ k: "failures", v: "14 in 5 minutes" }, { k: "app", v: "Mail" }, { k: "reviewed by", v: "nobody yet" }],
            context: "A rule matched. It might be an attack, or a phone still holding last month's password.",
            answer: "alert", why: "A rule matched, so a person has to look. Most alerts turn out to be false positives, which is why an alert is not yet an incident.",
          },
          {
            id: "svc", time: "01:12", severity: "High", rule: "Remote service created on server", entity: "OAK-BILL-02",
            fields: [{ k: "ServiceName", v: "PSEXESVC" }, { k: "AccountName", v: "LocalSystem" }, { k: "Installed by", v: "adm-r.dale" }, { k: "reviewed by", v: "nobody yet" }],
            context: "IT patches on Saturdays with this same tool, and nobody has opened the change calendar yet.",
            answer: "alert", why: "High is the rule's label, not a verdict. Until someone checks the change calendar this is an alert. Keep an eye on this one: it comes back in Deck 2.",
          },
          {
            id: "call", time: "02:10", severity: "Low", rule: "Rare outbound connection", entity: "OAK-ENG-LT03",
            fields: [{ k: "process", v: "rclient.exe" }, { k: "RemoteIP", v: "198.51.100.24:443" }, { k: "analyst", v: "process tree reviewed, true positive" }, { k: "owner", v: "r.dale, on leave, phoned: 'not me'" }],
            context: "The first call of the night: the duty controller at Hallow Bridge works rang because the engineer's laptop on the bench was moving its own pointer. You pulled the record and rang the owner.",
            answer: "incident", why: "The lowest label in the log, and the only incident. An analyst weighed the evidence and the owner denied it. That determination is what makes an incident, and the moment it is made the response starts.",
          },
        ],
      },
      {
        kind: "sort",
        title: "Which Phase Owns This Job?",
        prompt: "Before the next card, Imogen tests the table. Oakhollow's playbook uses PICERL, the six phases SANS teaches: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned. Put each job in the phase it belongs to. The ones that sound alike are the ones teams get wrong at 03:00.",
        buckets: [
          { id: "p", label: "Preparation" },
          { id: "i", label: "Identification" },
          { id: "c", label: "Containment" },
          { id: "e", label: "Eradication" },
          { id: "r", label: "Recovery" },
          { id: "l", label: "Lessons Learned" },
        ],
        items: [
          { id: "p1", text: "Agree who may isolate a host at 02:00 without asking first", bucket: "p", why: "Done before anything happens: defences, training, playbooks. Preparation decides how every later phase goes. NIST SP 800-61's classic four-phase model calls this phase Preparation too." },
          { id: "p2", text: "Run a tabletop and fix what it embarrasses in the playbook", bucket: "p", why: "Practice is Preparation. SP 800-61 Rev 3 (April 2025) reorganised response around the six Cybersecurity Framework 2.0 functions, but the four phases are still the clearest way to learn the mechanics, and most SOCs work from PICERL." },
          { id: "i1", text: "Ring a laptop's owner to ask whether that activity was theirs", bucket: "i", why: "Is it real? You are confirming a true positive. NIST calls this phase Detection & Analysis." },
          { id: "i2", text: "Search the VPN logs for how the intruder first got in", bucket: "i", why: "How did it happen? You need the entry point now, because Eradication has to close it." },
          { id: "i3", text: "List every host one stolen account has touched", bucket: "i", why: "How far has it gone? This is scope assessment: you cannot contain a blast radius you have not measured." },
          { id: "c1", text: "Block the command-and-control domain at the firewall", bucket: "c", why: "Stops the attacker's live access now, like stopping the bleeding before surgery. NIST rolls Containment, Eradication and Recovery into one phase; PICERL splits them because each needs different work." },
          { id: "c2", text: "Put a temporary block between the office and plant networks", bucket: "c", why: "Nothing is removed and nothing is fixed. The block only stops the attack crossing that boundary, and it comes off once the networks are clean." },
          { id: "e1", text: "Delete the scheduled task the intruder planted", bucket: "e", why: "Removal, not restriction. Containment holds the attacker in place; Eradication takes the attacker out." },
          { id: "e2", text: "Turn on MFA for the contractor VPN accounts", bucket: "e", why: "It feels like Preparation, but during an incident closing the way in is part of Eradication: patch the flaw, revoke the credentials, shut the door they used." },
          { id: "r1", text: "Reconnect rebuilt servers one group at a time", bucket: "r", why: "Restoring service safely. Everything is already clean: this phase is about getting it back without bringing the problem with it." },
          { id: "r2", text: "Watch restored hosts closely for the next 60 days", bucket: "r", why: "Enhanced monitoring, usually 30 to 90 days, because re-infection within weeks is common when something was missed." },
          { id: "l1", text: "Write down why the first sign-in went unnoticed for days", bucket: "l", why: "A detection gap, the kind of finding this phase exists for. NIST calls it Post-Incident Activity." },
          { id: "l2", text: "Give the missing detection rule an owner and a date", bucket: "l", why: "A finding without an owner changes nothing. What this phase produces feeds straight back into Preparation." },
        ],
      },
      {
        kind: "duel",
        title: "Who Takes This Card?",
        prompt: "An inject is a card the facilitator of a tabletop plays to change the situation. Imogen plays five. Each one lands on one seat at the table, and if it lands on the wrong seat it sits there unanswered. Play the seat that owns it.",
        attacker: "The inject deck",
        moves: [
          { id: "m1", move: "Two directors give opposite orders about the billing server", detail: "One says keep it up for month-end, the other says pull it. The analysts have stopped working until someone decides.", counter: "lead", hint: "Who makes the final call and owns the timeline?", why: "The IR Lead, or Incident Commander, makes the final decision. Without one named decider, the work stops while senior people argue." },
          { id: "m2", move: "A job at 01:30 writes to a finance share every night", detail: "The SOC has flagged it as odd. Nobody on the team can say whether it has always done that.", counter: "owner", hint: "Who knows what normal looks like on that system?", why: "System Owners are the business teams behind each system, and they can confirm what normal looks like. Asking them takes one call." },
          { id: "m3", move: "The billing database holds names and bank details", detail: "Nobody knows yet if it was read. Somebody needs to decide whether a clock has started.", counter: "legal", hint: "Who assesses notification duties?", why: "Legal/Compliance assesses regulatory notification, such as the GDPR 72-hour rule or SEC breach reporting. The technical team supplies the facts, Legal decides what they trigger." },
          { id: "m4", move: "A reporter rings the control room about the water", detail: "The reporter has heard about 'a hack at Oakhollow' and is asking if the water is safe to drink.", counter: "comms", hint: "Who speaks to people outside the team?", why: "The Communications Lead handles management, outside parties and regulators' notices, so one accurate message goes out. During containment that also covers executives, affected business units and, where needed, insurers and law enforcement." },
          { id: "m5", move: "The attacker's address appears in a report on another utility", detail: "Is this one crew working through the sector? What did they do next over there?", counter: "ti", hint: "Who brings attacker and campaign context?", why: "The Threat Intelligence Analyst provides attribution and campaign context, which tells the team what to look for next." },
        ],
        cards: [
          { id: "lead", name: "IR Lead", effect: "Incident Commander. Decides and owns the timeline." },
          { id: "analyst", name: "Tier-2/3 Analyst", effect: "Hands-on investigation, forensics, malware analysis." },
          { id: "comms", name: "Communications Lead", effect: "Tells management and outside parties." },
          { id: "legal", name: "Legal/Compliance", effect: "Assesses what the law requires." },
          { id: "ti", name: "Threat Intel Analyst", effect: "Who is behind it and what they do." },
          { id: "owner", name: "System Owner", effect: "Business team that runs the system." },
          { id: "bridge", name: "All-hands bridge call", effect: "Everyone on the line, nobody named." },
        ],
        lesson: "Each card has one owner, and an all-hands call is how a card ends up with none. A RACI matrix (Responsible, Accountable, Consulted, Informed) writes this down for every playbook task in advance, so nobody works it out at 02:00.",
      },
    ],
    // ── Reading 2: identification, evidence, containment ──
    "ir-method-r2": [
      {
        kind: "queue",
        title: "Rate the Incident Again as the Facts Arrive",
        prompt: "Deck 2. Your declaration at 02:10 started the clock. Identification answers three questions, and they sit on every card: is it real, how did they get in, how far have they gone? Rate each card on what is known at that moment. Two side tickets land in the middle of it, as they always do.",
        console: "Exercise log · Severity board",
        actions: [
          { id: "p4", label: "P4: minor, non-critical host", tone: "close" },
          { id: "p3", label: "P3: confirmed, limited scope", tone: "close" },
          { id: "p2", label: "P2: one system lost, no spread", tone: "escalate" },
          { id: "p1", label: "P1: domain admin, crown jewels or active spread", tone: "contain" },
        ],
        alerts: [
          {
            id: "first", time: "02:25", severity: "Medium", rule: "Remote tool on an engineering laptop", entity: "OAK-IR-2026-014",
            fields: [{ k: "Is it real?", v: "Yes: owner denied it, EDR shows rclient.exe" }, { k: "How did they get in?", v: "Not known yet" }, { k: "How far?", v: "OAK-ENG-LT03 only, no lateral movement seen" }, { k: "Data at risk", v: "Pump station drawings" }],
            context: "First rating of the night. Rate what is on the card, not what you fear.",
            answer: "p2", why: "One system compromised, no confirmed lateral movement, sensitive data at risk: P2. Senior analysts engaged, management notified.",
          },
          {
            id: "adware", time: "02:40", severity: "High", rule: "Adware detected and removed", entity: "OAK-KIOSK-07",
            fields: [{ k: "Asset", v: "Reception kiosk, no sensitive data" }, { k: "Action", v: "Removed by the agent" }, { k: "Spread", v: "None" }],
            context: "A side ticket. The product's own label says High.",
            answer: "p4", why: "One detection on a non-critical machine, already dealt with: P4, routine. A vendor's label is not your priority, and a big incident next door does not raise this one.",
          },
          {
            id: "script", time: "02:55", severity: "Low", rule: "Script tried to fetch an unknown file", entity: "OAK-FIN-PC22",
            fields: [{ k: "Confirmed", v: "Yes, a user ran a script from a forum" }, { k: "Result", v: "Download blocked, no foothold found" }, { k: "Spread", v: "None" }],
            context: "Another side ticket. It is real, but it stopped at one desk.",
            answer: "p3", why: "Suspicious activity confirmed, limited scope, nothing compromised: P3, standard SOC analyst response.",
          },
          {
            id: "scope", time: "03:10", severity: "Medium", rule: "Same account on two more hosts", entity: "OAK-IR-2026-014",
            fields: [{ k: "Is it real?", v: "Yes" }, { k: "How did they get in?", v: "Not known yet" }, { k: "How far?", v: "adm-r.dale from OAK-ENG-LT03 to OAK-BILL-02 and OAK-HIST-01" }, { k: "Account rights", v: "Member of Domain Admins" }, { k: "Change ticket", v: "None for the 01:12 service" }],
            context: "The 01:12 alert from Deck 1 has come back: there was no patching on Saturday.",
            answer: "p1", why: "Same incident, one new fact, new rating. An intruder holding domain admin on crown jewel systems is P1: all hands and immediate executive notification. Severity follows the scope.",
          },
          {
            id: "quiet", time: "03:30", severity: "Low", rule: "Intruder session dropped", entity: "OAK-IR-2026-014",
            fields: [{ k: "Is it real?", v: "Yes" }, { k: "How did they get in?", v: "ext-tvp-svc on the VPN, no MFA on contractor accounts" }, { k: "First sign-in", v: "Tue 3 Nov 23:47 from 203.0.113.58" }, { k: "How far?", v: "3 hosts, 1 domain admin account" }, { k: "Active now", v: "No session for 40 minutes" }, { k: "VPN log retention", v: "90 days, set after last year's tabletop" }],
            context: "The duty manager suggests stepping this down until Monday, since it has gone quiet.",
            answer: "p1", why: "Quiet is not gone: the intruder still holds domain admin, so it stays P1. And write down that date. The intruder arrived ten days before the first call, which Recovery will need, and you can only see it because Preparation kept the logs.",
          },
        ],
      },
      {
        kind: "defuse",
        title: "Evidence Before the Power Lead",
        prompt: "Deck 3. Three hosts were confirmed at 03:30, the quiet has not lasted, and the room wants them gone. RAM holds running processes, open connections, keys and tools that never touched the disk, and all of it dies with the power. Each module is one moment at a host: read it, then cut the one decision that fits.",
        device: "the evidence clock",
        seconds: 95,
        rounds: [
          {
            id: "spread",
            state: "OAK-BILL-02: a PsExec service is starting on one neighbour after another, one a minute. The duty manager has a hand on the power lead.",
            wires: [{ id: "power", label: "Pull the power lead, that stops it cold" }, { id: "iso", label: "EDR network isolation" }, { id: "mem", label: "Take a RAM image first, then decide" }],
            cut: "iso",
            hint: "It is moving right now. What stops the movement and costs no evidence?",
            why: "Something that is actively spreading gets isolated first. EDR network isolation cuts everything except the link to the EDR cloud, and the host stays powered on, so RAM survives. The power lead stops the spread too, and destroys the evidence with it. Imaging first leaves it spreading for the length of the capture.",
          },
          {
            id: "quiet",
            state: "OAK-HIST-01: one idle beacon to 198.51.100.24 every 30 minutes, nothing moving, and a responder already at the console. Oakhollow's playbook says capture first when nothing is spreading.",
            wires: [{ id: "cap", label: "Capture memory first, then isolate" }, { id: "iso", label: "Isolate at once, capture whatever is left" }, { id: "wipe", label: "Reimage it tonight, before it wakes up" }],
            cut: "cap",
            hint: "Nothing is moving, so what do you gain by waiting a few minutes?",
            why: "With nothing spreading, some teams capture before isolating, so they can see the command-and-control session while it is alive. The moment something starts to spread, that choice goes away and isolation comes first.",
          },
          {
            id: "first",
            state: "OAK-ENG-LT03 is isolated and still running. You have one responder for the next ten minutes. What gets collected first?",
            wires: [{ id: "ram", label: "RAM image through the EDR" }, { id: "disk", label: "Shut down cleanly, then image the disk" }, { id: "scan", label: "Full antivirus scan, to see what is there" }],
            cut: "ram",
            hint: "Which of these disappears if the laptop stops?",
            why: "Memory first, through the EDR's own acquisition or a tool such as WinPMEM or DumpIt, then network state and running processes, and only then think about powering down or reimaging. The disk survives a shutdown and RAM does not. Carried forward: this image is the one that will show which accounts were dumped.",
          },
          {
            id: "custody",
            state: "The image is finished, and Legal says this could end up in court. An analyst wants to open it straight away to start on the accounts.",
            wires: [{ id: "hash", label: "Hash it, log it, seal it, use a copy" }, { id: "ro", label: "Open the original read-only, so it cannot change" }, { id: "share", label: "Copy it to the team share now, log it later" }],
            cut: "hash",
            hint: "How would you prove in a year that nobody touched it?",
            why: "Chain of custody: record who collected each item, when and how, hash digital evidence, track every handover, and never work on the original. Break the chain and the evidence may be inadmissible.",
          },
        ],
        lesson: "Spreading means isolate first. Quiet gives you the option of capturing first. Either way RAM goes before anything that shuts down or reimages, and the original stays sealed while you work on a verified copy. Powering off and isolating are not the same thing: only one of them keeps the evidence alive.",
      },
      {
        kind: "reactor",
        title: "Stop It Now, Hold It Stable, or Later?",
        prompt: "Deck 4. Everyone is shouting actions at once. Short-term containment stops active access right now. Long-term containment makes that hold durable once the fire is out. Some of what is being shouted belongs to a later phase, and doing it now costs you. Route each one before it reaches the end of the belt.",
        reactors: [
          { id: "short", label: "SHORT-TERM", sub: "stop it right now" },
          { id: "long", label: "LONG-TERM", sub: "make the hold durable" },
          { id: "later", label: "LATER PHASE", sub: "not containment" },
        ],
        items: [
          { id: "vlan", text: "Move OAK-BILL-02 to the quarantine VLAN", reactor: "short", why: "Network engineering can do this in minutes, and it cuts lateral movement at once." },
          { id: "fw", text: "Block 198.51.100.24 at the perimeter firewall", reactor: "short", why: "Cuts the live C2 channel for every host at once." },
          { id: "reset", text: "Reset the passwords of accounts used on the affected hosts", reactor: "long", why: "A durable control once the immediate fire is out. Include any account that could have been stolen from those hosts." },
          { id: "revoke", text: "Revoke sessions and tokens for ext-tvp-svc", reactor: "long", why: "A password reset alone leaves a live session running." },
          { id: "iocs", text: "Push every C2 indicator to all security controls", reactor: "long", why: "One firewall rule was the emergency fix. This covers every control, for as long as the incident runs." },
          { id: "task", text: "Delete the intruder's tools from the servers", reactor: "later", why: "That is Eradication. Do it now and you may destroy evidence and warn the intruder before the scope is known." },
          { id: "restore", text: "Restore billing data from a backup", reactor: "later", why: "That is Recovery. You cannot restore onto systems you have not cleared." },
          { id: "report", text: "Start the post-incident report", reactor: "later", why: "That is Lessons Learned. For now, just keep accurate notes: they will become the timeline." },
        ],
      },
      {
        kind: "outbreak",
        title: "Contain It Before It Reaches SCADA",
        prompt: "Deck 5. A second copy of the intruder's tool has woken up and is moving through the works' network towards the control system that runs the pumps. Every turn you isolate one host, then it moves one link. Reading the map is the skill: isolate where one cut protects the most hosts. The network is different every run.",
        hostPrefix: "OAK",
        cols: 6,
        rows: 5,
        crown: "SCADA",
        via: "PsExec with the stolen domain admin account",
        lesson: "Containment is a race with a shape. A cut behind the spread saves nothing, and a cut ahead of it, where the network narrows, saves everything behind it. Every host you isolate stays powered on, so its RAM is still there. And every host it reaches is one more for Eradication to clean and Recovery to restore: delay here is paid for in the next two phases.",
      },
    ],
    // ── Reading 3: eradication, recovery, lessons learned ──
    "ir-method-r3": [
      {
        kind: "inspect",
        title: "Read the Eradication Sheet",
        prompt: "Deck 6. The spread has stopped. Imogen hands you the sheet the team built overnight. Open every line and read where it came from: half of it only exists because of decisions made in earlier decks.",
        artifact: "OAK-IR-2026-014 · Eradication sheet",
        items: [
          { id: "accounts", text: "Source: memory image, OAK-ENG-LT03. Accounts dumped: adm-r.dale, svc-hist, svc-bill", tag: "Carried from Containment", tone: "info", note: "The reset list comes straight from the RAM you kept. Only adm-r.dale was ever seen moving between hosts. Without the image this line would be a guess." },
          { id: "files", text: "Remove: rclient.exe, its dropper, recon tools and the staging folder, 14 hosts including OAK-DC01 and OAK-NAS-02", tag: "Remove the malware", tone: "warn", note: "Not just the file that alerted: droppers, recon tools, C2 components and staging locations go too. Then run a full disk scan with updated signatures." },
          { id: "persist", text: "Persistence: scheduled task on OAK-BILL-02, WMI subscription on OAK-HIST-01", tag: "Remove persistence", tone: "warn", note: "Assume more than one. Check scheduled tasks, registry Run keys, startup folders, WMI subscriptions, browser extensions, modified services and the boot sector." },
          { id: "door", text: "Close the way in: disable ext-tvp-svc, MFA on all contractor VPN accounts", tag: "Carried from Identification", tone: "info", note: "Identification found the entry point, and this closes it: patch the flaw, revoke the credentials, block the delivery route. Leave it open and everything else on this sheet is temporary." },
          { id: "resets", text: "Reset: every account usable from the 14 hosts, not only the 3 dumped", tag: "Reset credentials", tone: "warn", note: "Reset anything the attacker could have reached from a compromised system, not just the user whose account was breached." },
          { id: "krbtgt", text: "KRBTGT: reset twice, with replication in between. OAK-DC01 was reached with Domain Admin rights", tag: "Kerberos", tone: "warn", note: "KRBTGT is the account whose key signs every Kerberos ticket in the domain. Resetting it invalidates all tickets, forged ones included. It is done twice because the account keeps its previous password." },
          { id: "rebuild", text: "OAK-BILL-02: doubt remains after clean-up. Rebuild from known-clean image", tag: "Rebuild if uncertain", tone: "trust", note: "Any doubt, especially on a critical server, means rebuild: it is often faster than a forensic hunt and it guarantees a clean result. Carried forward: a rebuilt server has no data, so Recovery has to restore it." },
        ],
      },
      {
        kind: "queue",
        title: "Eradicate, Then Recover: Approve, Hold or Refuse",
        prompt: "Deck 7. Sunday, and everyone wants their systems back. As Incident Commander for this deck you get proposals, not alerts. Approve the right step, hold a right step that is too early, refuse a wrong one. Read what each card carries forward: the next card is built on it.",
        console: "Exercise log · Commander's desk",
        actions: [
          { id: "approve", label: "Approve", tone: "contain" },
          { id: "hold", label: "Hold: right step, too early", tone: "escalate" },
          { id: "refuse", label: "Refuse: wrong step", tone: "close" },
        ],
        alerts: [
          {
            id: "narrow", time: "Sun 09:10", severity: "High", rule: "Reset adm-r.dale only", entity: "IT manager",
            fields: [{ k: "Phase", v: "Eradication" }, { k: "Carried in", v: "Memory image lists 3 dumped accounts" }, { k: "Argument", v: "'It's the only one we saw moving between hosts, and resets hurt.'" }],
            context: "The IT manager wants to keep the disruption small on a Sunday.",
            answer: "refuse", why: "What you watched is not what was stolen. The image names three accounts, and the rule is everything reachable from those hosts. Carries forward: the full reset goes ahead, so a spare account cannot walk the intruder back in.",
          },
          {
            id: "laptop", time: "Sun 10:30", severity: "Medium", rule: "Put OAK-ENG-LT03 back on the network", entity: "Hallow Bridge works manager",
            fields: [{ k: "Phase", v: "Eradication" }, { k: "rclient.exe", v: "Removed" }, { k: "Persistence check", v: "Not run on this host yet" }, { k: "EDR scan", v: "Queued" }],
            context: "The engineer is needed on Monday, and the file is gone.",
            answer: "hold", why: "The goal is fine and the moment is wrong. Deleting one file is not eradication: verify first, with the scan and every persistence location. Carries forward: the laptop goes back later, but it goes back clean.",
          },
          {
            id: "rebuild", time: "Sun 13:00", severity: "Medium", rule: "Rebuild OAK-BILL-02 from the known-clean image", entity: "Tier-3 analyst",
            fields: [{ k: "Phase", v: "Eradication" }, { k: "Clean-up so far", v: "2 implants removed, doubt remains" }, { k: "Cost", v: "Billing offline for 8 hours" }],
            context: "The analyst would rather stop hunting and start again from a known state.",
            answer: "approve", why: "Doubt on a critical server means rebuild. Carries forward: a clean server with empty data folders, so the next card is about which backup fills them.",
          },
          {
            id: "restore", time: "Sun 16:00", severity: "High", rule: "Restore billing data from the 2 Nov backup", entity: "Backup administrator",
            fields: [{ k: "Phase", v: "Recovery" }, { k: "Carried in", v: "First sign-in Tue 3 Nov 23:47" }, { k: "Backups held", v: "13 Nov, 9 Nov, 2 Nov" }, { k: "Cost", v: "12 days of meter readings to re-key" }],
            context: "The finance director wants the 13 Nov copy, which loses almost nothing.",
            answer: "approve", why: "A restore point has to pre-date first access, not the alarm. The two newer copies were taken with the intruder already inside. This decision was only possible because Identification looked past the alarm in Deck 2.",
          },
          {
            id: "allatonce", time: "Sun 18:00", severity: "Medium", rule: "Reconnect all 38 hosts at 06:00", entity: "Chief operating officer",
            fields: [{ k: "Phase", v: "Recovery" }, { k: "Quarantined", v: "38: the 14 compromised, plus 24 cut off around them in Deck 5" }, { k: "Verified clean", v: "38 of 38" }, { k: "Argument", v: "'They're all clean. Flip it back.'" }],
            context: "The Monday shift starts at 07:00.",
            answer: "refuse", why: "Verified clean still returns in stages: one group at a time, watched closely. If something was missed it shows on group one, with the rest still safe.",
          },
          {
            id: "watch", time: "Sun 20:00", severity: "Low", rule: "Heightened monitoring for 60 days", entity: "SOC lead",
            fields: [{ k: "Phase", v: "Recovery" }, { k: "Scope", v: "Affected hosts and others like them" }, { k: "Cost", v: "Extra analyst review each shift" }],
            context: "The dull card of the day, and the budget holder is frowning.",
            answer: "approve", why: "30 to 90 days is normal, because re-infection within weeks is common when eradication missed something. Include similar systems as well as the ones that were hit.",
          },
          {
            id: "close", time: "Sun 21:30", severity: "Medium", rule: "Declare the incident closed tonight", entity: "Chief executive",
            fields: [{ k: "Phase", v: "Recovery" }, { k: "Hosts back", v: "12 of 38" }, { k: "Regulator", v: "Update owed on Monday" }],
            context: "The chief executive wants to tell the board it is over.",
            answer: "hold", why: "Right words, too early: 26 hosts are still out. The incident closes when service is back and verified, and the post-incident review follows that.",
          },
        ],
      },
    ],
    // ── Drill: what each shortcut costs ──
    "ir-method-q2": [
      {
        kind: "defuse",
        title: "Run B: What Each Shortcut Costs",
        prompt: "Deck 8. Imogen sweeps the cards up and deals the same incident again, as played by a team at another utility that took the fast option every time. Each module is a bill arriving for one of their shortcuts. Find the best move left.",
        device: "the review clock",
        seconds: 90,
        rounds: [
          {
            id: "ram",
            state: "Run B pulled the plug on the engineering laptop at 02:20. No memory image exists, so nobody knows which accounts were dumped. Eradication starts now.",
            wires: [{ id: "all", label: "Treat every account on it as stolen" }, { id: "one", label: "Reset only adm-r.dale, the one seen moving hosts" }, { id: "boot", label: "Boot the laptop and look in RAM after all" }],
            cut: "all",
            hint: "RAM does not come back after a reboot. What is left to base the list on?",
            why: "RAM is gone for good, and a reboot brings back nothing. With no evidence of what was taken, the reset list has to cover everything that could have been. Lost evidence comes back as a bigger, more disruptive job.",
          },
          {
            id: "date",
            state: "Run B stopped at the alarm and logged the compromise as Sat 14 Nov. The VPN log says the first sign-in was Tue 3 Nov. Their backups are dated 13 Nov, 9 Nov and 2 Nov.",
            wires: [{ id: "nov13", label: "Restore 13 Nov, the night before the alarm" }, { id: "nov9", label: "Restore 9 Nov, five days back to be safe" }, { id: "nov2", label: "Restore 2 Nov, the oldest copy" }],
            cut: "nov2",
            hint: "Count from the first sign-in, not from the alarm.",
            why: "A clean backup has to pre-date the initial compromise, not the trigger. Attackers wait inside for days or weeks, so a backup from the night before the alarm can already hold what they planted. Restoring it puts their foothold back.",
          },
          {
            id: "return",
            state: "Six days after Run B's recovery, enhanced monitoring catches ext-tvp-svc signing in from 203.0.113.58 again. The team had removed the tool and never closed the VPN account.",
            wires: [{ id: "reopen", label: "Reopen it and close the way in" }, { id: "rest", label: "Restore the same backup and check it again" }, { id: "pw", label: "Change that password, close the ticket again" }],
            cut: "reopen",
            hint: "Is this a new incident, or the old one that was never finished?",
            why: "Re-infection within weeks usually means eradication was incomplete. It goes back up the chain: contain, scope it again, and close the entry point this time. Monitoring is why they saw it at all.",
          },
          {
            id: "notes",
            state: "Run B kept no notes. In the review nobody can say when containment began, and the chief executive asks for the name of whoever was on shift.",
            wires: [{ id: "time", label: "Rebuild the timeline from logs" }, { id: "name", label: "Give the name so the meeting can move on" }, { id: "skip", label: "Skip the timeline, go straight to the actions" }],
            cut: "time",
            hint: "What does this meeting produce, and what stops people telling the truth in it?",
            why: "The review is factual, not a blame session: people who expect blame stop reporting what really happened. Logs and tickets can rebuild most of a timeline, and every gap in it is a finding of its own.",
          },
        ],
        lesson: "Every phase is paid for by the one after it. Lost RAM makes Eradication bigger. A short look-back poisons Recovery. An open door brings the whole incident back. Missing notes leave the review with nothing to learn from. The shortcut always felt faster at the time.",
      },
    ],
    // ── Drill: the post-incident report ──
    "ir-method-q5": [
      {
        kind: "hotspot",
        title: "Mark Up the Review Draft",
        prompt: "Back to your own run. The incident is closed, and a junior manager has drafted the post-incident report. Imogen wants it marked up before it goes anywhere. Tap everything that would make this report useless or harmful. Lines that are fine will tell you why.",
        artifact: "OAK-IR-2026-014 · Post-incident report, draft 1",
        finish: "What is left is a factual record of what failed and who will change it, with no names to punish.",
        parts: [
          { id: "title", text: "Post-incident report: OAK-IR-2026-014", flag: false, style: "subject", note: "A plain title with the case number. The report keeps its link to the tickets and the evidence." },
          { id: "date", text: "Review meeting: held within the 24 to 72 hour window after resolution", flag: false, style: "meta", note: "Fine. The meeting happens while memories and logs are still fresh." },
          { id: "timeline", text: "Timeline: first access 3 Nov 23:47, detected 14 Nov 02:10, contained 14 Nov 04:05.", flag: false, style: "body", note: "This is right: when it began, when it was detected, when it was contained. The gap between the first two numbers is the most important fact in the report." },
          { id: "cause", text: "Root cause: human error by the night duty analyst.", flag: true, style: "body", note: "That is a name, not a root cause. The fundamental failure is the one that let this happen: no MFA on contractor VPN accounts." },
          { id: "gap", text: "Detection gap: a first sign-in from a new address raised no rule, and VPN logs were not in the SIEM.", flag: false, style: "body", note: "Good. Why did it take this long, what log source was missing, which rule did not fire?" },
          { id: "well", text: "What worked: the phone tree, and isolation within 12 minutes of the P1 rating.", flag: false, style: "body", note: "This section matters too. It tells the next team what to keep doing." },
          { id: "vague", text: "Action: improve logging.", flag: true, style: "body", note: "No owner and no deadline, so nothing will happen. An action item says what, who and by when." },
          { id: "good", text: "Action: VPN logs into the SIEM, plus a new-address sign-in rule. Owner p.khan, by 30 November.", flag: false, style: "body", note: "This one is specific, owned and dated, which is what the meeting is supposed to produce." },
          { id: "hr", text: "Appendix: staff who failed to act, passed to HR for follow-up.", flag: true, style: "body", note: "This is not a blame session. Do this once and the next team will hide what really happened from you." },
        ],
      },
    ],
    // ── Drill: read the record before the boss ──
    "ir-method-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Disguised Process",
        prompt: "Last sheet in the folder before Imogen packs the cards away: the EDR record behind the 01:12 service on OAK-BILL-02. A real alert gives you one host and one name. Read this one field by field for what it really says about the process and about the scope.",
        source: "EDR process record · OAK-BILL-02",
        fields: [
          { key: "Timestamp", value: "2026-11-14T01:12:44Z", label: "When" },
          { key: "DeviceName", value: "OAK-BILL-02.oakhollow.example", label: "Where" },
          { key: "ActionType", value: "ProcessCreated" },
          { key: "FileName", value: "spoolsv.exe", label: "The name it wears", note: "A real Windows name: the print spooler. A familiar name proves nothing, because anyone can give a file any name." },
          { key: "FolderPath", value: "C:\\ProgramData\\OakSync\\spoolsv.exe", label: "Where it really sits", note: "Core Windows binaries such as this one live in C:\\Windows\\System32\\. The right name in the wrong folder is Masquerading, ATT&CK T1036.005: judge a process by name and path together." },
          { key: "InitiatingProcessFileName", value: "cmd.exe", label: "Who started it", note: "The real spooler is a service started by services.exe. A shell as its parent is a second tell, independent of the path." },
          { key: "AccountName", value: "adm-r.dale", label: "As whom", note: "A domain admin account, so this one record already pushes the rating up." },
          { key: "ProcessCommandLine", value: "spoolsv.exe --push \\\\OAK-HIST-01\\C$ \\\\OAK-NAS-02\\exports$", label: "What it reached", note: "Two more machines, written in the record. The alert was raised on one host, and the scope is every host the evidence names: this record is how OAK-NAS-02 got onto the containment list." },
        ],
        summary: "Read the path as well as the name, the parent as well as the process, and every host a record mentions, not only the host it was raised on. A record that names three machines is a three-machine incident, whatever the alert title says.",
      },
    ],
  },
};
