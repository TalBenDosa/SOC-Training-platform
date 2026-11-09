import type { RoomExperience } from "./types";

// "Operation Autopilot" for the "soar-automation" room.
// Script: docs/campaign/66-soar-automation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Cobalt Ridge Logistics (fictional), not the graded tasks' nexacorp records.
// Signature: Trust the Automation? The learner runs a phishing playbook on real cases
// (simulate: each check decides what the playbook does) and sets what may run with no human
// (tune: too strict and the analysts drown, too loose and the bot disables the CEO).
// Game mix: defuse + duel + tune.
//
// New task order (the room lists every reading first, and la2 and ac1 need r3 and r4 before them):
// soar-r1, soar-q1, soar-r2, soar-q2, soar-o1 | soar-r3, soar-q3, soar-m1 |
// soar-la1, soar-la2, soar-r4 | soar-ac1, soar-flag1
//
// Lab data differs from the graded tasks: the order lab is an EDR malware playbook, never the
// phishing report (o1); the raw alert is a disabled leaver's account over Remote Desktop, never
// a wrong password on a service account (la1); the enriched case is a suspicious sign-in on a
// finance user with a bulletproof-hosting tag, never a Tor node on a backup account, and its
// bundle is block plus isolate, never block plus disable (la2); token theft in the duel follows
// a password change, never a disabled account (r3 checkpoint); the boss drills use API 401s and
// an MQTT broker, never Windows failed logons, their causes are a token issuer move and a user
// store migration, never a password rotation, and their tickets and addresses differ (ac1, flag1).

export const SOAR_AUTOMATION: RoomExperience = {
  roomId: "soar-automation",
  codename: "Operation Autopilot",
  theme: "autopilot",
  handler: { name: "Freya Dlamini", role: "SOAR Engineer, Cobalt Ridge Logistics" },
  briefing: [
    "Cobalt Ridge Logistics. 640 people, four depots, and a chilled freight fleet that never stops.",
    "At 07:12 on Monday a phishing playbook disabled the CEO's account, 48 minutes before the biggest contract signing in the company's history.",
    "No human saw it happen. The board wants the bot switched off, and the four analysts say they will drown without it.",
    "Freya Dlamini has until Friday to show what may run alone. Learn the playbook, run it on real cases, and set the line yourself.",
  ],
  mission: "Separate the SIEM's job from the SOAR's, order a playbook, match each containment action to the move it stops, run the phishing playbook on real cases, read an alert before and after enrichment, set what may run with no human, then decide what happens to a block the playbook is asking for.",
  estimate: "~50 min",
  look: { primary: "#7aa2f7", secondary: "#fde68a", warn: "#fb5607" },
  scene: "facilityautopilot",
  layout: "facility",
  story: {
    intro: { title: "07:12", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-intro-9394a0dd.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-intro-e29023e2.jpg" },
    afterStation: {
      playbook: { title: "What Ran", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-ch2-ea76c034.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-ch2-297fa9e1.jpg" },
      gate: { title: "Until Friday", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-ch3-6c758d7e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-ch3-6e32f350.jpg" },
      trust: { title: "Trust", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-finale-e9c4efd7.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soar-automation/autopilot-finale-929d9d12.jpg" },
    },
  },
  stations: [
    {
      id: "playbook",
      label: "The Playbook",
      topic: "SOAR vs SIEM · orchestration, automation, response · playbooks · enrichment lookups",
      tagline: "What actually ran on Monday?",
      building: "control",
      taskIds: ["soar-r1", "soar-q1", "soar-r2", "soar-q2", "soar-o1"],
    },
    {
      id: "gate",
      label: "The Gate",
      topic: "Containment actions · confidence and blast radius · human in the loop",
      tagline: "The bot can. Should it?",
      building: "vault",
      taskIds: ["soar-r3", "soar-q3", "soar-m1"],
    },
    {
      id: "dial",
      label: "The Dial",
      topic: "Raw vs enriched alerts · case management · auto-triage · MTTR · over-automation",
      tagline: "Drown the analysts or trust the bot",
      building: "lab",
      taskIds: ["soar-la1", "soar-la2", "soar-r4"],
    },
    {
      id: "trust",
      label: "Trust the Automation?",
      topic: "Reading the enrichment behind a recommended action, and citing the cause",
      tagline: "It is asking for your approval",
      building: "ticket",
      taskIds: ["soar-ac1", "soar-flag1"],
      boss: true,
    },
  ],
  personas: {
    "soar-q1": { name: "Freya Dlamini", role: "SOAR Engineer", line: "The board keeps asking what we bought. Give me the one-line answer." },
    "soar-q2": { name: "Freya Dlamini", role: "SOAR Engineer", line: "What do we call this step on the review slide?" },
    "soar-o1": { name: "Freya Dlamini", role: "SOAR Engineer", line: "Lay the run out for the review, first step to last." },
    "soar-q3": { name: "Freya Dlamini", role: "SOAR Engineer", line: "The CFO wants to know why we buy speed and then make it wait." },
    "soar-m1": { name: "Freya Dlamini", role: "SOAR Engineer", line: "Half the review board has never seen a playbook. Match these up for them." },
    "soar-la1": { name: "Freya Dlamini", role: "SOAR Engineer", line: "This is the alert as it arrived, nothing added." },
    "soar-la2": { name: "Freya Dlamini", role: "SOAR Engineer", line: "Same alert, after the playbook finished its work." },
    "soar-ac1": { name: "Freya Dlamini", role: "SOAR Engineer", line: "It has a recommendation waiting. Your name goes on the decision." },
    "soar-flag1": { name: "Freya Dlamini", role: "SOAR Engineer", line: "The case record needs one reference from you." },
  },
  briefings: {
    // ── Reading 1: what SOAR is, and what it is not ──
    "soar-r1": [
      {
        kind: "sort",
        title: "Detector, Sprinkler or Analyst?",
        prompt: "The board thinks the bot replaced everything. Freya draws a building: the SIEM is the smoke detector, the SOAR is the sprinkler plus the automatic call to the fire department, and someone still has to walk in afterwards. Sort each job at Cobalt Ridge to whoever really does it.",
        buckets: [
          { id: "siem", label: "SIEM: the smoke detector" },
          { id: "soar", label: "SOAR: the sprinkler and the call" },
          { id: "human", label: "Analyst: the judgment call" },
        ],
        items: [
          { id: "i1", text: "Ingests logs from all four depots and correlates them", bucket: "siem", why: "Collecting and correlating is the detection engine's work. A SOAR platform does not replace it, and a playbook has nothing to run on until the SIEM raises something." },
          { id: "i2", text: "Decides that something worth looking at just happened, and raises the alert", bucket: "siem", why: "That is the smoke detector making noise. It is valuable, but it stops there: it does not call anyone or fix anything." },
          { id: "i3", text: "Takes that alert and runs the same five lookups in seconds, not fifteen minutes", bucket: "soar", why: "The mechanical, repeatable part of the work. Without a playbook this is an analyst clicking through consoles for ten to fifteen minutes per alert." },
          { id: "i4", text: "Opens a ticket and quarantines a mail in one flow, the moment the alert lands", bucket: "soar", why: "This is the sprinkler: it starts on rules set in advance, instead of waiting for someone to walk over and turn a valve." },
          { id: "i5", text: "Decides whether an odd sign-in is an intruder or a partner having a bad day", bucket: "human", why: "This is the judgment part, roughly the last 10% of the work. SOAR clears the mechanical 90% so this gets a person's full attention." },
          { id: "i6", text: "Inspects the damage afterwards and signs off the incident report", bucket: "human", why: "After a sprinkler fires, someone still decides if the building is safe. SOAR extends the SIEM and supports the analyst. It replaces neither." },
        ],
      },
      {
        kind: "match",
        title: "Three Words in the Name",
        prompt: "SOAR is Security Orchestration, Automation and Response. Monday's run did all three, and that is how it did so much damage so fast. Match each word to what it looks like in a playbook run, and spot the word that is not in the name.",
        pairs: [
          { id: "orch", left: "Orchestration", right: "One flow asks the mail gateway, the directory and the case queue, and joins their answers", why: "Orchestration is the coordination across tools: many systems, one flow. Integrations, which are API connections to each tool, make it possible." },
          { id: "auto", left: "Automation", right: "The same steps run at 03:00 with nobody touching a keyboard", why: "Automation is about who does the step: a machine, the same way every time. A step can be automated without touching a second tool." },
          { id: "resp", left: "Response", right: "The flow quarantines a mail because the playbook says so", why: "Response is acting on the alert from a predefined workflow, called a playbook. Enriching and ticketing count too; containment is the part that changes things." },
          { id: "corr", left: "Correlation (not in the name)", right: "Linking a VPN sign-in and a file download into one alert", why: "Correlation is the SIEM's job, done before any playbook starts. It is not one of the three words in SOAR." },
        ],
      },
    ],

    // ── Reading 2: playbooks and lookups ──
    "soar-r2": [
      {
        kind: "sequence",
        title: "Put a Playbook in Running Order",
        prompt: "A playbook is a predefined chain of steps, drawn as a flowchart, that fires on one type of alert. Here is Cobalt Ridge's playbook for a malware detection on a laptop. Tap the steps in the order they really run.",
        items: [
          { id: "draft", text: "Write the findings and a recommended action into the case", note: "This comes last of the machine's work: a summary can only hold what the lookups returned." },
          { id: "alert", text: "EDR raises a detection on CR-DISP-22, and a case opens in the SOAR platform", note: "Nothing runs until a trigger fires. A playbook is tied to one alert type." },
          { id: "decide", text: "An analyst reads the case and approves or changes the action", note: "The human comes after the machine has gathered everything, so the decision takes minutes, not half an hour." },
          { id: "look", text: "Run the lookups side by side: hash reputation, host owner, user role", note: "Lookups run in parallel, which is why five of them finish in seconds." },
          { id: "pull", text: "Pull the file hash, hostname and username out of the alert", note: "You cannot look up what you have not extracted, so this always comes before any lookup." },
        ],
        order: ["alert", "pull", "look", "draft", "decide"],
        doneNote: "Trigger, extract, look up, summarise, decide. Almost every playbook has this shape: the machine gathers, the person decides. Any report-driven playbook follows it too, with its own indicators.",
      },
      {
        kind: "sort",
        title: "Reads, Changes, Records or Sorts?",
        prompt: "A playbook is built from four kinds of step, and they carry very different risk. Freya wants every step of the rebuild labelled before it goes near the review. Sort these steps.",
        buckets: [
          { id: "enrich", label: "Enrichment: looks it up" },
          { id: "contain", label: "Containment: changes something" },
          { id: "case", label: "Case management: keeps the record" },
          { id: "triage", label: "Auto-triage: sorts the queue" },
        ],
        items: [
          { id: "s1", text: "Checks a file hash against a malware feed and EDR history", bucket: "enrich", why: "It gathers context and changes nothing anywhere, so it is safe to fully automate. A bare hash means little until something says what it is." },
          { id: "s2", text: "Fetches the sender domain's age and the recipient's department", bucket: "enrich", why: "Two lookups, zero changes. Each would cost an analyst two to five minutes in a separate console." },
          { id: "s3", text: "Puts a laptop into network quarantine", bucket: "contain", why: "This changes the live environment. If the judgment behind it is wrong, the automation becomes the incident." },
          { id: "s4", text: "Adds a deny rule on the firewall", bucket: "contain", why: "A deny rule is a change to production traffic, however fast and tidy it looks in a flowchart." },
          { id: "s5", text: "Keeps a timeline of what fired, what was found and who approved it", bucket: "case", why: "Every run creates or updates a case, so one auditable timeline exists for an audit or a post-incident review, not notes in people's heads." },
          { id: "s6", text: "Keeps a matching ticket in step in the service desk", bucket: "case", why: "Through an integration, the case and the ticket stay aligned in whatever tool the company already uses." },
          { id: "s7", text: "Splits incoming alerts into close, escalate and human queue before anyone looks", bucket: "triage", why: "Auto-triage acts on the lookup results to spend human attention where it is needed. It uses that context; it is not the gathering itself." },
        ],
      },
      {
        kind: "match",
        title: "Which Lookup Answers It?",
        prompt: "A raw alert holds bare facts: an address, a name, a hash. Each lookup turns one of them into meaning. Match each lookup to the question it answers and the source it asks.",
        pairs: [
          { id: "ip", left: "IP reputation", right: "Known bad, a Tor exit, a cloud range, or no history? Asks threat intel feeds", why: "An address means nothing alone. Feeds such as VirusTotal or AbuseIPDB say what the world knows about it." },
          { id: "hash", left: "File hash reputation", right: "Seen before, and flagged as malware? Asks engines, EDR history or a sandbox", why: "A hash identifies one exact file, so this can return a very confident answer." },
          { id: "user", left: "User or account", right: "Who is this, what is their role, and is the account privileged? Asks the directory or HR", why: "Active Directory, Entra ID or the HR system says who this is and where they normally sign in from." },
          { id: "geo", left: "Geo-IP", right: "Which country and city, and does that fit this person? Asks a location database", why: "Useful only against an expectation. A country on its own proves little." },
          { id: "asset", left: "Asset owner", right: "Which team owns this machine, and how critical is it? Asks the CMDB", why: "A CMDB (configuration management database) turns a hostname into an owner and a criticality." },
        ],
      },
    ],

    // ── Reading 3: containment and the gate. The room's signature, part one ──
    "soar-r3": [
      {
        kind: "duel",
        title: "One Action for Each Move",
        prompt: "Before the bot gets any authority back, Freya tests you on what each containment action really reaches. An intruder plays five moves seen at Cobalt Ridge this year. Play the one action that stops each move.",
        attacker: "The intruder",
        moves: [
          { id: "m1", move: "A loader beacons from dispatch laptop CR-DISP-22", detail: "It calls out every 60 seconds, and the forensic team wants its memory intact.", counter: "isolate", hint: "You need the machine alive but cut off.", why: "Isolation goes through the EDR agent: the laptop loses the network, keeps its channel to the security tools, and stays running so memory can be collected." },
          { id: "m2", move: "A phished password is about to be tried on new devices", detail: "A depot temp's account. No session has been opened yet, so the next sign-in is the threat.", counter: "disable", hint: "Stop it at the identity provider.", why: "Disabling flips the account at the identity provider, so new sign-ins fail. It reaches sign-ins that have not happened yet, and only those." },
          { id: "m3", move: "A password spray pounds the VPN portal", detail: "Every attempt comes from 203.0.113.77, a rented server with no business here.", counter: "block", hint: "One source, one place to stop it.", why: "A deny rule on the firewall or WAF stops traffic from that one address. It is cheap here, and dangerous when an address might be shared." },
          { id: "m4", move: "A cookie stolen by an infostealer is replayed from the intruder's own machine", detail: "The victim changed their password an hour ago, yet the mailbox is still being read.", counter: "revoke", hint: "The session was issued before the password changed.", why: "Changing a password stops new sign-ins, but a token already issued stays valid until it expires or is revoked. Revoking forces re-authentication. MFA does not help: a stolen token has already passed it. Isolating the victim's laptop or blocking the victim's address hits the wrong machine." },
          { id: "m5", move: "A known malware hash appears on a second laptop", detail: "Every source rates it malicious, with no benign sighting anywhere, and it is trying to run.", counter: "hash", hint: "Which card can be wrong the least?", why: "One exact file with no legitimate use anywhere: a false positive costs almost nothing and waiting costs a lot. This is the rare action that can fairly run with no human at all." },
        ],
        cards: [
          { id: "disable", name: "Disable the account", effect: "Identity provider refuses every new sign-in." },
          { id: "ticket", name: "Open a ticket", effect: "Writes the record. Stops nothing." },
          { id: "isolate", name: "Isolate the host", effect: "EDR cuts its network and leaves it running." },
          { id: "hash", name: "Ban the hash fleet-wide", effect: "EDR refuses to run that exact file." },
          { id: "watch", name: "Add to a watchlist", effect: "Watches the indicator. Stops nothing." },
          { id: "revoke", name: "Revoke sessions and tokens", effect: "Issued sessions die; re-authentication is forced." },
          { id: "block", name: "Block the address", effect: "Firewall or WAF denies one source." },
        ],
        lesson: "Each action reaches one layer: host, identity, network or session. All of them can fire in under a second, which is exactly why the real question is whether they should.",
      },
      {
        kind: "sort",
        title: "Where Does the Line Go?",
        prompt: "The line depends on two things: how confident you are, and the blast radius of being wrong, meaning how much breaks and how quickly you can undo it. Freya needs each Cobalt Ridge action put in its band for the rebuild.",
        buckets: [
          { id: "auto", label: "Runs with no human" },
          { id: "gate", label: "Waits at an approval gate" },
          { id: "must", label: "Senior approval, every time" },
        ],
        items: [
          { id: "b1", text: "Tag the case with the lure family", bucket: "auto", why: "Reversible and touching nothing in production. A wrong tag is a typo." },
          { id: "b2", text: "Post the case link to the SOC chat channel", bucket: "auto", why: "Notifying people has no blast radius, so there is nothing to gate." },
          { id: "b3", text: "Add a sender domain to a watchlist", bucket: "auto", why: "A watchlist watches. It blocks nothing, so being wrong costs only a little noise." },
          { id: "b4", text: "Isolate a dispatch clerk's laptop", bucket: "gate", why: "Disruptive but recoverable: one person loses an hour, and release is one click. The playbook drafts it and an analyst approves." },
          { id: "b5", text: "Disable a seasonal picker's account", bucket: "gate", why: "Low privilege, one person, easy to re-enable. It still changes the live environment, so a person clicks approve." },
          { id: "b6", text: "Isolate the warehouse management server CR-WMS-01", bucket: "must", why: "Every depot stops scanning pallets. Hard to absorb and affects shared systems, so a Tier 2 or manager approves every time, however strong the evidence." },
          { id: "b7", text: "Block the address all four depots use as their outbound gateway", bucket: "must", why: "A shared address means one rule takes out everyone behind it. A wrong block here is an outage you caused." },
          { id: "b8", text: "Disable svc-routeplan, which runs the nightly route planner", bucket: "must", why: "Production depends on this account, so a wrong disable stops trucks." },
        ],
      },
      {
        kind: "simulate",
        title: "Run Phish Report on Real Cases",
        prompt: "This is the rebuilt playbook, Phish Report v3, with three checks in front of every action. Run all four cases from this month, including Monday's. Watch which check stops the run, and what the playbook does next.",
        checks: [
          { name: "Lookups healthy", question: "Did every lookup return a real answer, not a timeout, an error or an empty result?" },
          { name: "Two sources agree", question: "Do two independent sources call it malicious, not one feed alone?" },
          { name: "Small if wrong", question: "If the verdict is wrong, is the damage small and quick to undo?" },
        ],
        scenarios: [
          {
            id: "s1", label: "Case 4102: dispatch clerk",
            detail: "case=4102 user=n.sithole dept=dispatch domain_age=2d url_feed=malicious(6) sandbox=credential_form same_mail=6 mailboxes action=quarantine_mail",
            results: ["pass", "pass", "pass"],
            why: ["Both lookups came back with real answers.", "The feed and the sandbox reached the same verdict independently.", "Pulling a mail from six mailboxes is undone with one restore."],
            verdict: "All three pass, so no human is needed. The playbook pulls all six copies, opens the ticket and logs why. This is what automation is for.",
          },
          {
            id: "s2", label: "Case 4117: finance director",
            detail: "case=4117 user=t.botha dept=finance role=director clicked=yes domain_age=4d url_feed=malicious(9) sandbox=credential_form action=disable_account",
            results: ["pass", "pass", "fail"],
            why: ["Lookups are healthy.", "Evidence is strong, stronger than case 4102.", "Disabling a director in the month-end payment run is not small, even if the verdict is right."],
            verdict: "The playbook drafts disable and revoke, then stops at the gate and pages Tier 2. Confidence decides what to recommend. Blast radius decides who pulls the trigger.",
          },
          {
            id: "s3", label: "Case 4123: locked archive",
            detail: "case=4123 user=m.pillay dept=customs attachment=docs.zip sandbox=no_verdict(archive encrypted) url_feed=none action=close_clean",
            results: ["fail", "fail", "pass"],
            why: ["No verdict is not a verdict. The sandbox never saw inside the archive.", "Nothing called it malicious, and nothing called it clean either.", "Closing would be easy to undo, which is why this one is so tempting."],
            verdict: "The playbook neither closes nor quarantines. It sends the case to Tier 1, marked attachment not analysed. Unknown is a result, and it goes to a person.",
          },
          {
            id: "s4", label: "Case 3977: Monday, 07:12",
            detail: "case=3977 user=a.ferreira role=CEO clicked=yes url=track.harlowfreight.example url_feed=malicious(1) last_seen=14mo sandbox=HTTP 429 no_result action=disable_account",
            results: ["fail", "fail", "fail"],
            why: ["The sandbox was rate limited and returned nothing, and v2 carried on without it.", "One engine, a stale entry from 14 months ago, on a real partner's tracking portal.", "The CEO's account, 48 minutes before the signing."],
            verdict: "v2 had no checks: one stale hit plus one failed lookup became a disable with no human. v3 stops at the first check. The playbook was not wrong about what to do with a bad link. It was wrong to believe its own lookups.",
          },
        ],
      },
    ],

    // ── Log analysis 1: the raw alert ──
    "soar-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Raw Failed-Logon Alert",
        prompt: "This alert fired at Cobalt Ridge last week, before any playbook touched it: 14 failures in 9 minutes against a driver scheduler who left in June. Scan the marked fields and note what each one can tell you, and what none of them can.",
        source: "Windows Security · SIEM alert, raw",
        fields: [
          { key: "event.code", value: "4625", label: "What happened", note: "4625 is a failed logon, for any account of any kind. A success is 4624." },
          { key: "hostname", value: "CR-RDS-02.cobaltridge.example" },
          { key: "winlog.event_data.TargetUserName", value: "k.naidoo", label: "Who was targeted", note: "The account name, and nothing about who that is or what it can reach." },
          { key: "winlog.event_data.TargetDomainName", value: "CRL", label: "Which domain", note: "The domain is already in the event. No lookup needed." },
          { key: "winlog.event_data.Status", value: "0xC000006E" },
          { key: "winlog.event_data.SubStatus", value: "0xC0000072", label: "Why it failed", note: "SubStatus gives the reason: 0xC000006A is a wrong password, 0xC0000064 no such user, 0xC0000072 a disabled account. Here the account is already disabled." },
          { key: "winlog.event_data.LogonType", value: "10", label: "How it was tried", note: "2 is at the keyboard, 3 is over the network, 10 is Remote Desktop." },
          { key: "winlog.event_data.IpAddress", value: "198.51.100.24", label: "Where from", note: "Only a number. Nothing here says whether it is hostile, a partner, or has ever been seen before." },
          { key: "winlog.event_data.FailureReason", value: "%%2310" },
        ],
        summary: "The raw event says exactly what happened and nothing about what it means. An analyst would now spend ten minutes finding that out, and that is the gap a playbook fills.",
      },
      {
        kind: "sort",
        title: "Already There, or Needs a Lookup?",
        prompt: "Same k.naidoo alert. A lookup is only worth writing into a playbook if the answer is not already in the event. Sort each fact: can you read it off the raw event, or does it need a lookup?",
        buckets: [
          { id: "raw", label: "Already in the raw event" },
          { id: "lookup", label: "Needs a lookup" },
        ],
        items: [
          { id: "a1", text: "That the account was disabled when tried", bucket: "raw", why: "SubStatus 0xC0000072 says so. Every failure reason sits in that field." },
          { id: "a2", text: "That this was Remote Desktop", bucket: "raw", why: "LogonType 10 says so." },
          { id: "a3", text: "Which domain k.naidoo belongs to", bucket: "raw", why: "TargetDomainName carries it." },
          { id: "a4", text: "What threat feeds think of 198.51.100.24", bucket: "lookup", why: "No log line carries an outside opinion. That takes a reputation feed." },
          { id: "a5", text: "Any earlier visit from that address in 90 days of logs", bucket: "lookup", why: "One event knows nothing about the past. That takes a search of history, which is exactly what a playbook automates." },
          { id: "a6", text: "Which team runs CR-RDS-02, and how critical it is", bucket: "lookup", why: "The hostname is a name. Owner and criticality live in the CMDB." },
        ],
      },
      {
        kind: "inspect",
        title: "Who Is Behind the Account?",
        prompt: "An alert's priority changes with the kind of account it names. Open Freya's notes on these directory facts.",
        artifact: "Directory notes · accounts that failed logon this month",
        items: [
          { id: "h", text: "k.naidoo: person, driver scheduler (left in June)", tag: "Human account", tone: "info", note: "Repeated failures on a person's account have everyday explanations: a typo, caps lock, a phone holding an old password. The explanation has to be ruled out before you worry." },
          { id: "s", text: "svc-routeplan: runs the nightly route planner", tag: "Service account", tone: "warn", note: "A process supplies this credential from storage, so human error does not explain repeated failures on it. Accounts like this are valuable to attackers, so the same failure count deserves a harder look here." },
        ],
      },
      {
        kind: "inspect",
        title: "Two Logon Myths",
        prompt: "Tuesday's label printers stopped at the Eastgate depot, and the help desk's first notes on the outage contain two claims that are wrong. Open each one and read Freya's correction.",
        artifact: "Help desk notes · label printer outage",
        items: [
          { id: "l", text: "Service accounts are exempt from lockout", tag: "Myth", tone: "warn", note: "Service accounts are not exempt from lockout. That is the danger: locking one out with repeated failures can stop production." },
          { id: "m", text: "A wrong-password failure means MFA was bypassed", tag: "Myth", tone: "warn", note: "A wrong-password failure stopped at the password. It never reached MFA, so it says nothing about MFA being bypassed." },
        ],
      },
    ],

    // ── Log analysis 2: the enriched case ──
    "soar-la2": [
      {
        kind: "anatomy",
        title: "Anatomy of an Enriched Case",
        prompt: "A playbook has finished with a sign-in alert on a finance user. Everything below was added by lookups. Scan the marked fields and work out which ones really move the verdict.",
        source: "SOAR case record · CASE-5120, after the playbook",
        fields: [
          { key: "playbook.name", value: "Suspicious Sign-In v4" },
          { key: "enrichment.ip_reputation.score", value: "4/91 malicious", label: "How to read a score", note: "4 engines say malicious. The others mostly have no opinion, because most engines have simply never seen a given address. They are not 87 votes for clean, and 4 independent verdicts is a real signal." },
          { key: "enrichment.ip_reputation.tags", value: "[\"bulletproof-hosting\"]", label: "What the address is", note: "A tag says what the infrastructure is used for, which often counts for more than the number beside it." },
          { key: "enrichment.geoip.country", value: "Portugal", label: "The weakest line", note: "You could already see the address was external. A country alone proves little in either direction." },
          { key: "enrichment.user_context.normal_source_ips", value: "[\"10.40.2.0/24\"]", label: "The strongest line", note: "This compares the event with the account's own history. A sign-in from outside the only range it has ever used turns a number into a story." },
          { key: "enrichment.asset_owner.team", value: "Finance Systems" },
          { key: "enrichment.asset_owner.criticality", value: "high" },
          { key: "playbook.action_recommended", value: "block_ip_and_isolate_server", label: "Two actions in one", note: "A bundle. Blocking the address is cheap. Isolating a high-criticality server is not, and the gate has to cover the riskier half, however strong the evidence for the cheap half." },
          { key: "playbook.approval_required", value: "true" },
          { key: "playbook.approval_status", value: "pending", label: "Not done yet", note: "Recommended, not executed. Pending means waiting on a person." },
        ],
        summary: "Two bare facts became a case, and the deciding line was the one comparing this event with this user's normal, not the country. The strong evidence still stops at a person, because being wrong would hit a critical server.",
      },
      {
        kind: "evidence",
        title: "Read the Run Log",
        prompt: "A run log shows what a playbook did, step by step. Freya pulled three this month. Say what each one shows, then read the numbered clues.",
        choices: [
          { id: "clean", label: "Finished alone, safely" },
          { id: "gate", label: "Paused for a human" },
          { id: "bad", label: "Acted on a failed lookup" },
        ],
        items: [
          {
            id: "e1", caption: "Case 5120", answer: "gate",
            screen: { type: "soarrun", playbook: "Suspicious Sign-In v4", trigger: "SIEM alert: sign-in outside normal range", steps: [
              { name: "Extract indicators", result: "1 IP, 1 user, 1 host", ok: true },
              { name: "IP reputation", result: "4/91 malicious, bulletproof-hosting", ok: true },
              { name: "User context", result: "normal range 10.40.2.0/24", ok: true },
              { name: "Recommend", result: "block_ip_and_isolate_server", ok: true },
              { name: "Approval", result: "pending, assigned to tier-2", ok: false },
            ] },
            callouts: [{ at: "steps", text: "The last step is pending and nothing follows it. The action is drafted, and no firewall or EDR step has run." }],
          },
          {
            id: "e2", caption: "Case 3977", answer: "bad",
            screen: { type: "soarrun", playbook: "Phish Report v2", trigger: "User report, a.ferreira", steps: [
              { name: "Extract indicators", result: "1 URL, 1 sender", ok: true },
              { name: "URL reputation", result: "malicious (1 engine), last seen 14 months ago", ok: true },
              { name: "Sandbox", result: "HTTP 429, no result", ok: false },
              { name: "Disable account", result: "a.ferreira disabled 07:12", ok: true },
            ] },
            callouts: [{ at: "steps", text: "A failed step sits directly above a completed action, and no approval step exists at all. A tick only means a step ran: the feed's stale answer shows one too." }],
          },
          {
            id: "e3", caption: "Case 4102", answer: "clean",
            screen: { type: "soarrun", playbook: "Phish Report v3", trigger: "User report, n.sithole", steps: [
              { name: "Extract indicators", result: "1 URL, 1 sender", ok: true },
              { name: "URL reputation", result: "malicious (6 engines), seen today", ok: true },
              { name: "Sandbox", result: "credential form captured", ok: true },
              { name: "Quarantine mail", result: "6 copies pulled", ok: true },
              { name: "Ticket", result: "opened with the justification logged", ok: true },
            ] },
            callouts: [{ at: "steps", text: "Healthy lookups, two independent sources, and an action one restore can undo. No gate was needed, and the justification is on record." }],
          },
        ],
      },
    ],

    // ── Reading 4: over-automation. The room's signature, part two ──
    "soar-r4": [
      {
        kind: "defuse",
        title: "Bad Lookup, Live Run",
        prompt: "Freya replays four runs from the old playbook with the clock on. Each is seconds from acting on something it should not believe. Cut the wire that fits.",
        device: "Phish Report v2",
        seconds: 95,
        rounds: [
          {
            id: "d1",
            state: "URL feed answers HTTP 429. The error branch writes score=100. Next step: quarantine the mail in every mailbox.",
            wires: [
              { id: "w1", label: "Cut the error branch: no answer means unknown, send it to the queue" },
              { id: "w2", label: "Let it run: quarantine is reversible, restore it later if wrong" },
              { id: "w3", label: "Cut the feed: drop that lookup and decide on the rest" },
            ],
            cut: "w1",
            hint: "What does a 429 actually tell you about the link?",
            why: "A rate limit says nothing about the link. Writing a score on failure invents evidence, and every step below it inherits the lie. A failed lookup means unknown.",
          },
          {
            id: "d2",
            state: "Directory says the recipient is Staff, blast radius low. The record last synced 41 days ago. HR shows a promotion to the executive team last month.",
            wires: [
              { id: "w1", label: "Trust the directory: it is the system of record" },
              { id: "w2", label: "Skip the impact check for this one run" },
              { id: "w3", label: "Hold at the gate: the impact score rests on stale data" },
            ],
            cut: "w3",
            hint: "How old is the answer?",
            why: "A lookup can succeed and still be wrong. An old record gave a low blast radius for someone who is now an executive, and a person catches that where a green tick does not.",
          },
          {
            id: "d3",
            state: "Each ticket update re-triggers the playbook. In 3 minutes it has queued disable_account for 212 users from one campaign.",
            wires: [
              { id: "w1", label: "Let it finish, then re-enable everyone in bulk" },
              { id: "w2", label: "Stop the run and cap actions per run" },
              { id: "w3", label: "Raise the feed score needed for this run" },
            ],
            cut: "w2",
            hint: "Is this a verdict problem or a volume problem?",
            why: "A loop has no judgment to tune, so a stricter score changes nothing. Speed is the danger: a hard cap on actions per run turns a company-wide lockout into one strange alert.",
          },
          {
            id: "d4",
            state: "URL reputation 0/91, no tags. The domain was registered three hours ago. Next step: close as clean and tell the reporter it is safe.",
            wires: [
              { id: "w1", label: "Delete the mail everywhere: new means bad" },
              { id: "w2", label: "Let it close: not one engine flagged it" },
              { id: "w3", label: "Block the close: no history is not a clean bill" },
            ],
            cut: "w3",
            hint: "How long has anyone had to form an opinion?",
            why: "Zero detections on a three-hour-old domain means no engine has seen it yet. A clean score only counts alongside something else that explains the source. New is not proof of bad either, so a person decides.",
          },
        ],
        lesson: "Every action inherits the weakest lookup beneath it. Timeout, rate limit, stale record, no history: all of them mean unknown, and unknown never earns an unattended action.",
      },
      {
        kind: "tune",
        title: "The Trust Dial",
        prompt: "The review is Friday. Twelve closed cases from the last 30 days, with what the playbook scored them. Set the two dials that decide when the bot may act with no human. Anything outside them lands in the queue of four analysts. Too strict and they drown; too loose and it happens again.",
        howTo: [
          "Each row is a closed case: its confidence score and its blast radius, from 1 (one junk mail pulled) to 10 (an executive locked out).",
          "The bot acts alone only at or above the confidence dial AND at or below the blast radius dial. Press Deploy to replay them.",
          "Caught is a real phish handled alone, false is a legitimate case the bot hit, missed went to an analyst. Deploys are limited.",
        ],
        eventColumn: "closed case",
        dials: [
          { id: "conf", label: "Confidence the bot must reach", short: "confidence", min: 50, max: 100, step: 1, start: 98 },
          { id: "blast", label: "Most blast radius it may touch alone", short: "blast radius", min: 1, max: 10, step: 1, start: 1, dir: "below" },
        ],
        events: [
          { id: "p1", label: "Real phish: credential link, one picker's mailbox", bad: true, values: { conf: 97, blast: 2 } },
          { id: "p2", label: "Real phish: fake fuel-card invoice, dispatch clerk", bad: true, values: { conf: 94, blast: 3 } },
          { id: "p3", label: "Real phish: fake customs fee, 40 drivers", bad: true, values: { conf: 91, blast: 4 } },
          { id: "p4", label: "Real phish: lookalike portal, one depot temp", bad: true, values: { conf: 88, blast: 2 } },
          { id: "p5", label: "Real phish: fake payslip attachment, depot admins", bad: true, values: { conf: 87, blast: 4 } },
          { id: "p6", label: "Real phish: hijacked thread, finance director", bad: true, values: { conf: 95, blast: 9 } },
          { id: "p7", label: "Real phish: QR lure with thin evidence, credit clerk", bad: true, values: { conf: 72, blast: 3 } },
          { id: "n1", label: "Legitimate: CEO opens a partner link, one stale feed hit", bad: false, values: { conf: 96, blast: 10 } },
          { id: "n2", label: "Legitimate: partner portal on shared hosting, sales team", bad: false, values: { conf: 90, blast: 5 } },
          { id: "n3", label: "Legitimate: payroll provider's real reset mail", bad: false, values: { conf: 85, blast: 4 } },
          { id: "n4", label: "Legitimate: customer manifest zip, sandbox timed out", bad: false, values: { conf: 84, blast: 3 } },
          { id: "n5", label: "Legitimate: awareness test from the training vendor", bad: false, values: { conf: 93, blast: 8 } },
        ],
        goal: { catch: 5, maxFalse: 0 },
        deploys: 4,
        lesson: "Look at what is left for the analysts: the finance director's thread and the thin QR lure, which are the two cases that need a person. And look at the CEO's case: it scored 96. Confidence is what the feed claims, not what is true, so confidence alone can never set the line. The blast radius dial caught what the score could not.",
      },
      {
        kind: "sort",
        title: "Close, Escalate or Queue?",
        prompt: "Auto-triage sorts alerts into three lanes before any person looks, based on lookup results. The goal is not fewer humans; it is human attention on the alerts that need it. Sort these for Cobalt Ridge.",
        buckets: [
          { id: "close", label: "Auto-close, reason logged" },
          { id: "tier2", label: "Straight to Tier 2" },
          { id: "tier1", label: "Tier 1 queue, context attached" },
        ],
        items: [
          { id: "t1", text: "Allow-listed scanner sweeps the depot subnet in its approved Tuesday slot", bucket: "close", why: "The rule saw a real scan, so it fired correctly, and the approved schedule is what makes it authorised. Close it, and log the justification for audit." },
          { id: "t2", text: "Auditor's quarterly file transfer, matching an open ticket, trips a DLP rule", bucket: "close", why: "Strong, documented, benign context on record. The closure and its reason stay in the case." },
          { id: "t3", text: "Malware hash rated malicious by every source, on CR-WMS-01", bucket: "tier2", why: "Strong malicious indicators on a high-criticality asset: there is nothing to sort out at Tier 1, so it goes straight up with the context attached." },
          { id: "t4", text: "Known ransomware note appears on a depot file server", bucket: "tier2", why: "Clear and serious on shared infrastructure. Speed to the right person matters more than another look." },
          { id: "t5", text: "One engine flags a reported mail and the others are silent", bucket: "tier1", why: "Genuinely ambiguous, which is what the human queue is for. The lookups arrive attached, so the analyst starts at the judgment." },
          { id: "t6", text: "Driver signs in from a new country and the HR lookup timed out", bucket: "tier1", why: "A missing answer is not an answer in either direction. A person with the rest of the context decides." },
        ],
      },
      {
        kind: "worksheet",
        title: "Did the Bot Earn Its Keep?",
        prompt: "The board wants numbers, not a feeling. MTTR, mean time to respond, is the average time from an alert firing to the response being complete. Work out Freya's three figures for phishing alerts.",
        caption: "Phishing alerts, month by month",
        columns: ["Month", "Alerts", "Handled with no human", "MTTR (minutes)"],
        rows: [
          ["March, before SOAR", "2,400", "0", "18"],
          ["June, with playbook v2", "2,520", "1,512", "6"],
        ],
        questions: [
          { id: "w1", q: "By how many minutes did MTTR fall?", hint: "Subtract June's MTTR from March's.", answer: ["12", "12 min", "12 minutes"], why: "18 minus 6. MTTR is often the most visible win, because the lookups and first action now take seconds." },
          { id: "w2", q: "What percentage of June's alerts were handled with no human?", hint: "1,512 divided by 2,520.", answer: ["60", "60%"], why: "Alerts auto-handled is the second key metric. Note what it hides: a single wrong action like Monday's can hide in that 60%." },
          { id: "w3", q: "If each auto-handled alert saves 15 analyst minutes, how many hours did June reclaim?", hint: "Alerts times 15, then divide by 60.", answer: ["378", "378 hours", "378 h"], why: "1,512 times 15 is 22,680 minutes, or 378 hours. This is the figure that justifies the tool to leadership, and that time goes back to hunting and ambiguous cases." },
        ],
      },
    ],

    // ── Boss warm-up: weigh the enrichment against the recommendation ──
    "soar-ac1": [
      {
        kind: "sort",
        title: "Three Kinds of Alert That Fired",
        prompt: "When a rule fires there are three possibilities, and they get different fixes. Freya wants you to tell them apart before you touch anything the playbook recommends. Sort these Cobalt Ridge alerts.",
        buckets: [
          { id: "tp", label: "True positive: real and malicious" },
          { id: "btp", label: "Benign true positive: real, with a legitimate cause" },
          { id: "fp", label: "False positive: the rule misfired" },
        ],
        items: [
          { id: "c1", text: "Port-scan rule fires on the agreed pen test, from the agreed address, in its window", bucket: "btp", why: "The rule saw exactly what it targets, and the cause is authorised. The rule is working: close it, citing the authorisation." },
          { id: "c2", text: "Failed-auth rule fires on a backup agent whose certificate expired last night", bucket: "btp", why: "Real failures, legitimate source, known cause. Calling this a false positive invites someone to loosen a rule that is doing its job. Fix the certificate instead." },
          { id: "c3", text: "Failed-auth rule fires because a parser read a byte count as a failure count", bucket: "fp", why: "No failure ever happened. The rule misread its input, so the fix belongs in the rule or the parser." },
          { id: "c4", text: "Exfiltration rule fires because a regex matched a word in a URL, and no file moved", bucket: "fp", why: "The thing the rule targets did not occur. That is what false positive means." },
          { id: "c5", text: "A rented server tries one password against 300 accounts", bucket: "tp", why: "Real, and no legitimate explanation exists. This one is the rule doing its job on an actual attack." },
          { id: "c6", text: "A stolen API key downloads the customer table from a new address", bucket: "tp", why: "Real and malicious: the activity succeeded, on credentials nobody authorised for it." },
        ],
      },
      {
        kind: "queue",
        title: "Read the Enrichment, Not the Recommendation",
        prompt: "Four approvals are waiting, and in all four the playbook recommends a block. It has already gathered what you need, so read all of it, including how often the attempts come, before you decide.",
        console: "SOAR · Pending approvals",
        actions: [
          { id: "block", label: "Approve the block", tone: "contain" },
          { id: "close", label: "Reject and close, citing the cause", tone: "close" },
          { id: "esc", label: "Reject and escalate to Tier 2", tone: "escalate" },
        ],
        alerts: [
          {
            id: "a1", time: "Wed 09:40", severity: "Medium", rule: "API authentication failures", entity: "client_id tracklink-prod",
            fields: [
              { k: "Result", v: "410 HTTP 401, since 02:50" },
              { k: "Rhythm", v: "one every 60 seconds, steady" },
              { k: "Source", v: "198.51.100.40, unchanged" },
              { k: "Reputation", v: "no detections on any feed" },
            ],
            context: "Vendor register: address listed as the TrackLink carrier gateway. API history: 14 months of shipment-status calls from this address and nothing else. Change calendar: CHG-58204, customer API moved to a new token issuer Wednesday 02:45, carriers to repoint. Failures begin 02:50.",
            answer: "close",
            why: "Everything lines up: a listed owner, one narrow habit, and a change just before the first failure. Software pointed at the old issuer retries like a clock, where guessing tends to come in bursts. A block would cut the carrier off. Close it citing the change, and get the carrier repointed.",
          },
          {
            id: "a2", time: "Wed 09:52", severity: "High", rule: "API authentication failures", entity: "300 usernames",
            fields: [
              { k: "Result", v: "1,900 HTTP 401, in 4 minutes" },
              { k: "Rhythm", v: "bursts, many per second" },
              { k: "Source", v: "203.0.113.91" },
              { k: "Reputation", v: "6/91 malicious, tags: scanner" },
            ],
            context: "Vendor register: no entry. User context: usernames are customer logins with no shared integration. Change calendar: nothing touching this API this week.",
            answer: "block",
            why: "Bursty, across hundreds of accounts, with malicious verdicts and no owner and no change to explain it. One address with no business relationship means a low blast radius. This is what the block is for.",
          },
          {
            id: "a3", time: "Wed 10:05", severity: "Medium", rule: "API authentication failures", entity: "user r.vermeulen (credit control)",
            fields: [
              { k: "Result", v: "96 HTTP 401, over 8 hours" },
              { k: "Rhythm", v: "one every 300 seconds, steady" },
              { k: "Source", v: "203.0.113.150, a rented server" },
              { k: "Reputation", v: "0/91, no tags" },
            ],
            context: "Vendor register: no entry. User context: a person, who signs in from depot ranges only. Change calendar: nothing for this user or this API.",
            answer: "esc",
            why: "Steady and clean, but nothing explains it: no owner, no change, and a person's account never connects from a rented server. Steady rhythm alone clears nothing, because a patient attacker is steady too. That needs more than this panel can show, so it goes up. Neither a block nor a close is justified yet.",
          },
          {
            id: "a4", time: "Wed 10:18", severity: "Medium", rule: "API authentication failures", entity: "client_id tempcheck-prod",
            fields: [
              { k: "Result", v: "38 HTTP 401, then one HTTP 200" },
              { k: "After the 200", v: "bulk export from an endpoint never used before" },
              { k: "Source", v: "198.51.100.61" },
              { k: "Reputation", v: "0/91, no tags" },
            ],
            context: "Vendor register: address belongs to the TempCheck sensor gateway, ticket VND-0871. Change calendar: nothing touching this client.",
            answer: "esc",
            why: "A known vendor and a clean score are the same comfort as the first case, but there is no change to explain the failures, and a success followed by new behaviour is not a broken connector. The vendor may be compromised, and blocking it is a business decision. Tier 2 owns that call.",
          },
        ],
      },
    ],

    // ── Flag warm-up: who owns it is not why it broke ──
    "soar-flag1": [
      {
        kind: "trace",
        title: "Which Record Explains Why?",
        prompt: "The cold-store sensor gateway stopped reporting on Tuesday, and Freya wants the reason in the case record. Follow it from the broker log, and notice which record tells you what.",
        lead: "coldlink-gw, 10.60.4.12: failures at the sensor broker since Tuesday afternoon",
        steps: [
          {
            id: "t1",
            ask: "The gateway connects every 10 minutes. Click the first failure.",
            source: "Sensor broker auth log",
            columns: ["time", "client_id", "src_ip", "result"],
            rows: [
              ["Tue 15:48:10", "coldlink-gw", "10.60.4.12", "CONNACK 0: accepted"],
              ["Tue 15:58:10", "coldlink-gw", "10.60.4.12", "CONNACK 0: accepted"],
              ["Tue 16:08:10", "coldlink-gw", "10.60.4.12", "CONNACK 4: bad user name or password"],
              ["Tue 16:18:10", "coldlink-gw", "10.60.4.12", "CONNACK 4: bad user name or password"],
              ["Tue 16:28:10", "coldlink-gw", "10.60.4.12", "CONNACK 4: bad user name or password"],
            ],
            answer: 2,
            why: "Accepted at 15:58, refused at 16:08. Whatever changed, changed in those ten minutes. The start time is what you take to every other record.",
            learned: "First failure Tue 16:08:10; last success 15:58:10",
          },
          {
            id: "t2",
            ask: "Who owns this gateway? Click its register entry.",
            source: "Asset and vendor register",
            columns: ["record", "object", "owner", "purpose"],
            rows: [
              ["VND-1127", "dockcam-gw, 10.60.4.30", "Depot Security", "Dock camera uplink"],
              ["VND-1184", "coldlink-gw, 10.60.4.12", "Cold Chain Ops", "Cold-store sensor uplink"],
              ["VND-1190", "scalelink-gw, 10.60.4.44", "Depot Ops", "Weighbridge uplink"],
            ],
            answer: 1,
            why: "VND-1184 says the source is legitimate and whose it is. That is useful, and it would still read the same on a day when nothing was broken. It tells you who, not why.",
            learned: "VND-1184: owner Cold Chain Ops (says who, not why)",
          },
          {
            id: "t3",
            ask: "Which change explains the first failure? Click it.",
            source: "Change calendar",
            columns: ["change", "when", "object", "summary"],
            rows: [
              ["CHG-58690", "Mon 11:00", "dockcam-gw", "Firmware update"],
              ["CHG-58702", "Mon 15:20", "scalelink-gw", "Switch port moved"],
              ["CHG-58714", "Tue 09:30", "coldlink-gw", "Two freezers added to the sensor map"],
              ["CHG-58722", "Tue 16:02", "coldlink-gw", "Broker user store migrated, gateway account not carried over"],
              ["CHG-58731", "Tue 16:05", "svc-routeplan", "Password rotated by IT"],
              ["CHG-58740", "Wed 08:00", "coldlink-gw", "Firmware update"],
            ],
            answer: 3,
            why: "A cause comes before its effect, on the same object, and fits the failure. CHG-58714 is the right gateway but it ran fine for six and a half hours after. CHG-58731 falls in the right ten minutes but is the wrong account. CHG-58740 came after the failures began.",
            learned: "CHG-58722 explains the cause: the gateway lost its account six minutes before the first failure",
          },
        ],
      },
    ],
  },
};
