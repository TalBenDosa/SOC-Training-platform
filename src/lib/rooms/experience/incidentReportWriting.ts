import type { RoomExperience } from "./types";

// "Operation Final Report" for the "incident-report-writing" room.
// Script: docs/campaign/90-incident-report-writing.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Bellwether Schools Trust (fictional), mentor Priyanka Hale, IR Report Lead. The graded tasks
// stay on the Solstice Actuarial case file, which Priyanka hands to every new report writer.
// Signature: Write for Who Reads It. One incident becomes an executive summary, a technical
// timeline and a set of actions: `tune` sets how much detail each reader gets, and `spotdiff`
// marks up drafts against a clean version, tapping claims without evidence and blame.
// Game mix: intercept + spotdiff + tune.
//
// Task order CHANGED. Room order: r1, r2, q1, o1, r3, m1, la1, q2, r4, ac1, r5, qf1, q3, f1, q4, wr1.
// New order: r1, r2, q1, o1 | r3, m1, la1, f1, qf1 | r4, q2, ac1, q4 | r5, q3 | wr1.
// Why: q2 and q4 test defensibility, so both now follow r4, and f1 and qf1 read the la1 record,
// so they sit beside it. f1 carries its own `event` and no
// "Log Analysis N" wording, so it stays correct.
//
// Lab data differs from the graded tasks: the incident is a contractor's password on a gateway
// left out of an MFA rollout, then a file transfer from BW-MIS02. Its one scheduled task is a
// differently named IOC line in The IOC List Gate. It has no persistence story,
// no service account and no excess-privilege gap. Translated sentences are about parents' contact
// details, never a server for Accounts Payable (q1). Section order is shown once, in passing,
// in the anatomy of last year's mailbox report, and no lab asks for it (o1). The record is a
// DeviceNetworkEvents connection, never a task record (la1, f1); the query form uses another
// ActionType (qf1). The decision log is a portal pause, never a disabled server (q2). The
// verification alerts are a backup job, a scan and a bad feed entry, never an admin sign-in (ac1).
// Scope lines are about gateways and schools, never the graded host (q4). Filler actions are
// culture, feeds and encryption, never the two in q3. The practice write-ups are a clinic mailbox
// and a marking sheet with no case values (wr1). Nothing in a lab is a Solstice value.

export const INCIDENT_REPORT_WRITING: RoomExperience = {
  roomId: "incident-report-writing",
  codename: "Operation Final Report",
  theme: "finalreport",
  handler: { name: "Priyanka Hale", role: "IR Report Lead, Bellwether Schools Trust" },
  briefing: [
    "Bellwether Schools Trust. Fourteen schools, a small IT team, and an incident that closed on the Thursday of half term.",
    "The intruder is out. Now the chair of trustees, the data protection lead and the engineer rebuilding remote access all want the same report.",
    "Priyanka Hale has seen good investigations wasted by reports written for nobody in particular: true facts, wrong reader, no way to check them.",
    "Mark up the drafts, write for whoever reads it, then prove it on the Solstice Actuarial case file, the test Priyanka gives every new report writer.",
  ],
  mission: "Set how much detail each reader gets, read a finished report section by section, gate the IOC list, mark up a timeline, test claims against review, check what stays out, trace every action to a named gap, then write the two sections everyone reads.",
  estimate: "~55 min",
  look: { primary: "#f2a7c3", secondary: "#8fd6c8", warn: "#ff5f45" },
  scene: "facilityfinalreport",
  layout: "facility",
  stations: [
    {
      id: "reader",
      label: "The Reader",
      topic: "Two audiences · the executive summary · one document · the report's sections",
      tagline: "Who opens this first?",
      building: "office",
      taskIds: ["doc-r1", "doc-r2", "doc-q1", "doc-o1"],
    },
    {
      id: "record",
      label: "The Record",
      topic: "IOCs · the technical timeline · what goes in which section · evidence from a raw log",
      tagline: "Could a stranger search this?",
      building: "archive",
      taskIds: ["doc-r3", "doc-m1", "doc-la1", "doc-f1", "doc-qf1"],
    },
    {
      id: "review",
      label: "The Review",
      topic: "Defensibility · chain of custody · who, what, when, where, why, how · saying what you did not check",
      tagline: "Will it hold up in six months?",
      building: "control",
      taskIds: ["doc-r4", "doc-q2", "doc-ac1", "doc-q4"],
    },
    {
      id: "gap",
      label: "The Gap",
      topic: "Writing the root cause · recommendations that trace to it",
      tagline: "What let it succeed?",
      building: "lab",
      taskIds: ["doc-r5", "doc-q3"],
    },
    {
      id: "final",
      label: "Final Report",
      topic: "The Executive Summary and the Root Cause, in your own words",
      tagline: "The part everyone reads",
      building: "ticket",
      taskIds: ["doc-wr1"],
      boss: true,
    },
  ],
  personas: {
    "doc-q1": { name: "Priyanka Hale", role: "IR Report Lead", line: "This is a draft from the Solstice file. What do you tell its writer?" },
    "doc-o1": { name: "Priyanka Hale", role: "IR Report Lead", line: "Somebody shuffled the sections. Put them back." },
    "doc-m1": { name: "Priyanka Hale", role: "IR Report Lead", line: "Everything on this list has a home in the report." },
    "doc-la1": { name: "Priyanka Hale", role: "IR Report Lead", line: "Here's the record from the Solstice server. Build your sections from it." },
    "doc-f1": { name: "Priyanka Hale", role: "IR Report Lead", line: "The IOC section closes today. Give me the line." },
    "doc-qf1": { name: "Priyanka Hale", role: "IR Report Lead", line: "Show me how you got that record." },
    "doc-q2": { name: "Priyanka Hale", role: "IR Report Lead", line: "A reviewer has a question about something from three weeks ago." },
    "doc-ac1": { name: "Priyanka Hale", role: "IR Report Lead", line: "One more record from that night. Look at it before you decide." },
    "doc-q4": { name: "Priyanka Hale", role: "IR Report Lead", line: "The reviewer has circled one word in your timeline." },
    "doc-q3": { name: "Priyanka Hale", role: "IR Report Lead", line: "Read the draft's Recommendations and tell me what you think." },
    "doc-wr1": { name: "Priyanka Hale", role: "IR Report Lead", line: "Everyone reads these two parts. They're yours now." },
  },
  briefings: {
    // ── Reading 1: two audiences, one incident ──
    "doc-r1": [
      {
        kind: "sort",
        title: "Translated, or Just Shorter?",
        prompt: "Priyanka has pulled sentences from four drafts of the Bellwether summary. The chair of trustees will read it on a phone between meetings. Sort each sentence: did the writer translate it, or only make it shorter?",
        primer: {
          title: "What the first reader needs",
          points: [
            "The first reader is usually leadership or legal. They have four questions: **what happened, how bad is it, is it still happening, what is being done**.",
            "They need scope in business and risk terms: which services, whether people's data was involved, whether it is contained, and the impact you can responsibly estimate.",
            "An **executive summary** is three to six sentences at the very top of the report.",
            "It is a different piece of writing, not the technical section cut down. The question moves from 'what exactly happened' to 'what does this mean for us'.",
            "Every sentence in it must be something the technical section can back up.",
          ],
          example: {
            label: "One fact, two jobs (a dental practice's lost backup disk)",
            lines: [
              "Shorter: `Unencrypted USB volume lost; BitLocker not enforced by policy.`",
              "Translated: `A backup disk holding patient contact details has been lost. It was not encrypted, so we are treating those details as exposed, and the practice is contacting the regulator today.`",
            ],
          },
        },
        buckets: [
          { id: "translated", label: "Translated for the chair" },
          { id: "shorter", label: "Only shorter" },
        ],
        items: [
          { id: "t1", text: "An intruder used a contractor's password to get in through our old remote-access service.", bucket: "translated", why: "What happened, in words the chair already owns. Nothing needs looking up." },
          { id: "s1", text: "External Remote Services (T1133) via BW-RAS01 with valid credentials.", bucket: "shorter", why: "A technique name and number sort the event for analysts. The chair can do nothing with them, however short the line is." },
          { id: "t2", text: "Contact details of 1,180 parents and carers were copied out of the trust.", bucket: "translated", why: "Scope in people and data. The chair can see the size of it, and who has to be told." },
          { id: "s2", text: "rc.exe sent 41 MB over HTTPS to 203.0.113.58.", bucket: "shorter", why: "True and brief, and still a log line. It says nothing about what those 41 MB were or why they matter." },
          { id: "t3", text: "The intruder's access ended on 28 October and the old service has been switched off.", bucket: "translated", why: "This answers 'is it still happening' and 'what is being done' in one sentence." },
          { id: "s3", text: "A threat actor leveraged compromised credentials to achieve unauthorised data egress.", bucket: "shorter", why: "No IDs and no field names, and it is still written for analysts. 'Egress' forces a follow-up question. Removing the numbers isn't translating." },
          { id: "s4", text: "ActionType ConnectionSuccess on BW-MIS02 confirmed the outbound transfer.", bucket: "shorter", why: "A field name and its value belong where a technical reader can check them. Here they only slow the chair down." },
          { id: "t4", text: "Pupil attendance records at three schools were reachable; we found no sign they were copied.", bucket: "translated", why: "It separates what was reachable from what was taken, which is the distinction a chair has to repeat accurately." },
          { id: "s5", text: "Contractor credential abuse led to share enumeration and file access.", bucket: "shorter", why: "This is the technical narrative with words removed. The reader still has to ask what it means for the trust." },
        ],
      },
      {
        kind: "tune",
        title: "How Much Detail Does the Chair Get?",
        prompt: "All thirteen lines below are true. Tune Priyanka's red pen so it strikes everything the chair doesn't need and keeps six lines that answer the four questions.",
        eventColumn: "Line from the draft",
        mode: "any",
        dials: [
          { id: "terms", label: "Strike if terms to look up reach", short: "Terms", min: 1, max: 5, step: 1, start: 4 },
          { id: "asks", label: "Strike if questions answered are only", short: "Questions", dir: "below", min: 0, max: 3, step: 1, start: 1 },
        ],
        events: [
          { id: "k1", label: "An intruder used a contractor's password to get in through our old remote-access service.", bad: false, values: { terms: 0, asks: 1 } },
          { id: "b1", label: "rc.exe ran from C:\\Users\\Public\\Documents on BW-MIS02.", bad: true, values: { terms: 3, asks: 1 } },
          { id: "k2", label: "Contact details of 1,180 parents and carers were copied out of the trust.", bad: false, values: { terms: 0, asks: 1 } },
          { id: "b2", label: "Sign-in from 198.51.100.42 on BW-RAS01 at 2026-10-26T21:47:12Z.", bad: true, values: { terms: 3, asks: 1 } },
          { id: "b5", label: "The IT team's on-call rota changed during half term.", bad: true, values: { terms: 0, asks: 0 } },
          { id: "k3", label: "Pupil attendance records at three schools were reachable; we found no sign they were copied.", bad: false, values: { terms: 0, asks: 1 } },
          { id: "b3", label: "An SMB listing came before access to the Exports share.", bad: true, values: { terms: 2, asks: 1 } },
          { id: "k4", label: "The intruder's access ended on 28 October and the old service, BW-RAS01, is now switched off.", bad: false, values: { terms: 1, asks: 2 } },
          { id: "b6", label: "The gateway's supplier changed owners in 2024.", bad: true, values: { terms: 0, asks: 0 } },
          { id: "k5", label: "We are notifying the regulator and the affected families this week.", bad: false, values: { terms: 0, asks: 1 } },
          { id: "b4", label: "After containment, outbound HTTPS to 203.0.113.58 was blocked at the edge firewall.", bad: true, values: { terms: 3, asks: 1 } },
          { id: "k6", label: "Multi-factor sign-in now covers every route into the trust's network.", bad: false, values: { terms: 1, asks: 1 } },
          { id: "b7", label: "Overall, the response was broadly in line with good practice.", bad: true, values: { terms: 0, asks: 0 } },
        ],
        goal: { catch: 7, maxFalse: 0 },
        deploys: 3,
        howTo: [
          "Each row is one line of the draft. Terms counts what a chair would have to look up: IDs, addresses, file and protocol names. Questions counts how many of the four questions the line answers.",
          "The rule is a red pen: it strikes a line when either dial trips. Set both dials, then press Deploy the rule.",
          "The scoreboard speaks detection. An attack is a line that should go, and false is a line the chair needs that you struck. Caught means rightly struck, missed means it stayed in, quiet means a good line stayed.",
        ],
        lesson: "Seven of those thirteen lines were true and still had no place in the summary. Detail isn't wrong: it belongs further down the same report. A line stays in the summary when the chair can act on it without asking a follow-up, and a line that answers none of the four questions goes however plain it is.",
      },
      {
        kind: "spotdiff",
        title: "Two Files, Six Revisions Later",
        prompt: "Last year Bellwether wrote up a mailbox incident as two files, one for the board and one for IT. Priyanka finally laid them side by side. Tap every line in the board copy that no longer says what the IT copy says.",
        goodTitle: "IT copy, version 7 (BW-IR-2025-07)",
        suspectTitle: "Board copy, version 6 (BW-IR-2025-07)",
        good: [
          "Incident: forwarding rules on finance mailboxes",
          "Detected: 2025-03-11, by the mail team",
          "Mailboxes affected: 2",
          "Messages forwarded: 212",
          "Bank details in forwarded mail: yes, 3 supplier records",
          "Password reset: 2025-03-11",
          "Sessions revoked: 2025-03-12",
          "Supplier payments checked: yes",
          "Schools told: all 14",
          "Status: closed 2025-03-19",
        ],
        suspect: [
          "Incident: forwarding rules on finance mailboxes",
          "Detected: 2025-03-11, by the mail team",
          "Mailboxes affected: 1",
          "Messages forwarded: just over 200",
          "Bank details in forwarded mail: none found",
          "Password reset: 2025-03-11",
          "Sessions revoked: 2025-03-11",
          "Supplier payments checked: yes",
          "Schools told: all 14",
          "Status: closed 2025-03-19",
        ],
        diffs: [
          { line: 2, why: "One mailbox here, two in the IT copy. The second was found in revision 4, and that edit only went into one file." },
          { line: 4, why: "The worst one. A board that reads 'none found' won't ask about supplier payments, and three records were in that mail." },
          { line: 6, why: "A day out. Sessions were revoked the next morning, so the board copy shortens the time the intruder really had." },
        ],
        decoys: [
          { line: 3, why: "212 is just over 200. A plain round figure for the board says the same thing, so that's translation, not disagreement." },
        ],
        hud: "Tap the lines where the two files no longer agree",
        sameLine: "Those two lines say the same thing. The disagreement is somewhere else.",
        winTitle: "Every disagreement found",
        howTo: [
          "Read the IT copy on the left, then the board copy on the right.",
          "Tap a board line when it states a different fact from the IT line beside it.",
          "Plainer wording isn't a disagreement. Every false accusation costs a life.",
        ],
        lesson: "Nobody lied. Each edit reached only one file, so the two stopped agreeing and nothing warned anyone. That is drift. Bellwether now keeps one report, and both readers get their facts from it.",
      },
    ],
    // ── Reading 2: the anatomy of a complete report ──
    "doc-r2": [
      {
        kind: "anatomy",
        title: "A Finished Report, Section by Section",
        prompt: "Before you touch this year's report, read last year's finished one, the mailbox case, once it was merged into a single file. Scan each section to see what it does and who goes there.",
        source: "BW-IR-2025-07 · final report · section headings and a sample from each",
        fields: [
          { key: "Executive Summary", value: "Forwarding rules on two finance mailboxes sent 212 emails to an outside address for three days. Three suppliers' bank details were among them. The rules are gone, and every supplier payment has been checked.", label: "For leadership", note: "For anyone who will read only one part. Three to six sentences, business and risk terms." },
          { key: "Incident Overview", value: "Spotted by the mail team on 2025-03-11. One phished password, two mailboxes, a rule on each. Contained 2025-03-12.", label: "The bridge", note: "A few short paragraphs a technical reader can take in within a minute before going deeper." },
          { key: "Affected Systems & Data", value: "Mailboxes f.ames and d.rowe. 212 messages. 3 supplier bank records.", label: "The exact inventory", note: "Hosts, accounts, applications and data categories. Privacy and legal reviewers go straight here, because it decides who must be told, so 'some finance mail' won't do." },
          { key: "Evidence Sources & Analysis", value: "Unified Audit Log, New-InboxRule operations, pulled 2025-03-11 by m.adeyemi. Message trace for the outside address.", label: "How we know", note: "What was looked at and how each conclusion was reached. Another analyst should be able to walk the same path." },
          { key: "Technical Timeline", value: "2025-03-08T07:22:10Z: A rule forwarding all mail to an outside address was created on f.ames from an unfamiliar sign-in. From here, invoices left the trust unseen.", label: "Event by event", note: "One entry per event with a formal timestamp, from first access to recovery." },
          { key: "IOCs", value: "Email: billing@ledger-mail.example", label: "Searchable values", note: "A list a tool can use, lifted out of the timeline." },
          { key: "Root Cause", value: "The outbound mail policy allowed automatic forwarding to outside domains, and nothing alerted when a rule did it.", label: "What allowed it", note: "A control gap, not the attacker's actions. It needs everything above it to stand on." },
          { key: "Recommendations", value: "Block automatic forwarding to outside domains. Owner: mail team. Due 2025-04-01.", label: "What changes", note: "Concrete, assigned, checkable, and tied to the gap named just above it." },
        ],
        summary: "Eight named sections, the same every time. Nobody reads a report front to back: under time pressure each reader jumps to the part that answers their question, and a fixed structure is what lets them. A report that wanders forces every reader to hunt.",
      },
      {
        kind: "sort",
        title: "Where Would You Turn?",
        prompt: "This year's report isn't finished, and the questions have started. Send each person to the section that answers them.",
        buckets: [
          { id: "exec", label: "Executive Summary" },
          { id: "affected", label: "Affected Systems & Data" },
          { id: "evidence", label: "Evidence Sources & Analysis" },
          { id: "timeline", label: "Technical Timeline" },
          { id: "iocs", label: "IOCs" },
          { id: "recs", label: "Recommendations" },
        ],
        items: [
          { id: "a1", text: "Chair of trustees: is it over, and what do I tell the other trustees today?", bucket: "exec", why: "Meaning, status and impact, in plain language, in the part a chair can read in a minute." },
          { id: "a2", text: "Data protection lead: exactly which data categories could the intruder reach on BW-MIS02?", bucket: "affected", why: "The exact inventory is what decides notification, so this reader skips straight to it." },
          { id: "a3", text: "Engineer: what time did the gateway session start, and what came next?", bucket: "timeline", why: "Per-event entries with formal timestamps, in order." },
          { id: "a4", text: "Second analyst: which query showed the transfer, and can I run it myself?", bucket: "evidence", why: "Methodology lives here, along with the queries that produced each finding, so someone else can repeat the path." },
          { id: "a5", text: "Neighbouring trust's analyst: what can I paste into our own tools?", bucket: "iocs", why: "A list of discrete values for direct lookup, with no prose to dig through." },
          { id: "a6", text: "IT director: what are we changing, and who owns it?", bucket: "recs", why: "Corrective actions with an owner and a date." },
          { id: "a7", text: "Trust's lawyer: how many parents' records, and which fields?", bucket: "affected", why: "Numbers and data categories, stated exactly. Business impact in the summary points here for the detail." },
          { id: "a8", text: "Auditor: when was each fix finished?", bucket: "timeline", why: "The timeline runs all the way through containment, eradication and recovery. Those response times are often the first thing a review asks for." },
          { id: "a9", text: "Auditor: how did you conclude this account was the way in?", bucket: "evidence", why: "A conclusion and the reasoning from evidence to finding belong in the methodology section." },
        ],
      },
    ],
    // ── Reading 3: IOCs and the technical timeline ──
    "doc-r3": [
      {
        kind: "intercept",
        title: "The IOC List Gate",
        prompt: "The IOC list goes to the other trusts in the regional sharing group today, and each line will be pasted straight into their tools. Let through only what would work there. Keep the rest out.",
        protect: "the IOC list",
        blockLabel: "Keep out",
        passLabel: "List it",
        seconds: 12,
        primer: {
          title: "What an IOC line must be",
          points: [
            "An **IOC** (Indicator of Compromise) is an observable value an attacker left behind that another defender can search for.",
            "The section is a list for lookup, not a paragraph. **The test: could someone with no context paste this line into a search tool and get a meaningful result?**",
            "Write each value exactly. One mistyped character makes it unsearchable. Use a range only if a range is what was observed.",
            "Give full paths, because one file name can be fine in one folder and alarming in another.",
            "Label every hash with its algorithm, so a tool knows what it is matching.",
          ],
          example: {
            label: "One line that passes, one that doesn't (another trust's report)",
            lines: [
              "Passes: `Domain: updates-cdn.example`",
              "Fails: `a dodgy-looking site the user visited`",
            ],
          },
        },
        items: [
          { id: "i1", text: "IPv4: 203.0.113.58", sub: "The address the transfer went to, from the firewall log", bad: false, why: "One exact address, labelled, ready to paste." },
          { id: "i2", text: "IPv4 range: 203.0.113.0/24", sub: "An analyst's guess at the whole block. One address was seen", bad: true, why: "A range says you saw a range. Other trusts would hunt 256 addresses on the strength of one." },
          { id: "i3", text: "SHA256: 7be1c04fa93d52e816cd04b7f3a96e21d85c40f7ab12e693c7d0158ea46fb3d9", sub: "rc.exe, from the EDR record", bad: false, why: "The value and its algorithm together. A tool knows exactly what to match." },
          { id: "i4", text: "6f1e0c3ab87d4952e3c1a7f09d2b4e68", sub: "A hash with nothing written beside it", bad: true, why: "Which algorithm? A reader shouldn't have to guess from the length, and a tool matching the wrong type finds nothing." },
          { id: "i5", text: "File path: C:\\Users\\Public\\Documents\\rc.exe", sub: "Full path, as recorded", bad: false, why: "Name and location together make a finding others can hunt." },
          { id: "i6", text: "File name: rc.exe", sub: "The name alone", bad: true, why: "A short name on its own could be anything, anywhere. Without the path, a search returns noise." },
          { id: "i7", text: "Domain: files.quickdrop.example", sub: "As observed in the proxy log", bad: false, why: "Exactly as seen, so it matches when searched." },
          { id: "i8", text: "Domain: files.quikdrop.example", sub: "Retyped from a screenshot. The proxy log says quickdrop", bad: true, why: "One missing letter. It looks complete, and it will never match anything." },
          { id: "i9", text: "A suspicious tool that copied files out overnight", sub: "From the analyst's notes", bad: true, why: "It needs a sentence of explanation to be usable, so it belongs in the timeline or the evidence section." },
          { id: "i10", text: "Task name: PrintSpoolRefresh", sub: "From Task Scheduler on BW-MIS02, exactly as recorded", bad: false, why: "Task names are searched directly against other hosts' task schedulers, so the exact recorded name is the indicator." },
        ],
        lesson: "An IOC line has one job: work when a stranger pastes it. So it's one exact value, labelled with what it is. Anything that needs explaining goes in the timeline or the evidence section, where sentences belong.",
      },
      {
        kind: "spotdiff",
        title: "Mark Up the Timeline",
        prompt: "An analyst's first draft of the Bellwether timeline is on the right, and Priyanka's clean copy is on the left. Tap each draft line a reviewer could not stand behind: no evidence for it, blame, or a time nobody can check.",
        primer: {
          title: "One entry per event",
          points: [
            "Each entry has two parts: a formal timestamp, then a short passage on what happened and what it means.",
            "A formal timestamp has the full date, the time and the zone, like `2026-10-26T21:47:12Z`. The `Z` means UTC. 'About 20 minutes later' means nothing to a reader six months on, and can't be lined up against another system's records.",
            "Give the exact facts, then one grounded sentence of consequence: what this means for the intrusion, not a guess at intent.",
            "Cover the full life: first access, reconnaissance, movement, what was reached, then containment, eradication and recovery.",
            "Keep the response times. A review usually starts by asking how long detection to containment took, and containment to recovery.",
          ],
          example: {
            label: "One entry (a museum's report)",
            lines: [
              "`2026-02-11T03:05:41Z: m.lund signed in to MUS-DB01 from 10.2.0.77 over RDP.`",
              "`This gave the intruder an interactive session on the collections database.`",
            ],
          },
        },
        goodTitle: "Clean copy (p.hale)",
        suspectTitle: "Draft timeline, version 1",
        good: [
          "2026-10-26T21:47:12Z: ext.jkerr signed in to BW-RAS01 from 198.51.100.42, password only.",
          "This gave the intruder a session inside the trust's network.",
          "2026-10-26T22:03:40Z: 10.40.8.21 listed shares on BW-MIS02 and BW-FS03 over SMB.",
          "This showed the intruder where the exports were kept.",
          "2026-10-26T22:31:05Z: ext.jkerr opened \\\\BW-MIS02\\Exports and read 3 files.",
          "2026-10-26T23:12:33Z: rc.exe on BW-MIS02 connected to 203.0.113.58:443. The firewall counted 41 MB out.",
          "This is the point at which the contact records left the trust.",
          "2026-10-28T08:52:19Z: The EDR alert on rc.exe reached the SOC queue.",
          "2026-10-28T09:40:02Z: ext.jkerr disabled and BW-RAS01 shut down. Contained.",
          "2026-10-29T16:05:44Z: Remote access moved to the MFA gateway. Recovered.",
        ],
        suspect: [
          "2026-10-26T21:47:12Z: ext.jkerr signed in to BW-RAS01 from 198.51.100.42, password only.",
          "The contractor had clearly been careless, and this gave the intruder a session inside the network.",
          "About 15 minutes later: 10.40.8.21 listed shares on BW-MIS02 and BW-FS03 over SMB.",
          "This showed the intruder where the exports were kept.",
          "2026-10-26T22:31:05Z: ext.jkerr opened \\\\BW-MIS02\\Exports and read 3 files.",
          "2026-10-26T23:12:33Z: rc.exe on BW-MIS02 connected to 203.0.113.58:443. The firewall counted 41 MB out.",
          "This was without doubt a professional crew selling school data.",
          "2026-10-28T08:52:19Z: The EDR alert for rc.exe landed in the SOC queue.",
          "Wednesday morning: ext.jkerr disabled and BW-RAS01 shut down. Contained.",
          "2026-10-29T16:05:44Z: Remote access moved to the MFA gateway. Recovered.",
        ],
        diffs: [
          { line: 1, why: "Blame, and no evidence behind it. Nothing in the logs shows how the password left, so a timeline can't say it. The sign-in is the fact: state what it gave the intruder." },
          { line: 2, why: "A relative time. Later than what, for a reader who wasn't there? It can't be cross-referenced against any other system's records." },
          { line: 6, why: "A statement about motive that no record supports, written in the most confident words on the page. Say what this meant for the intrusion and stop there." },
          { line: 8, why: "No time, so nobody can measure detection to containment, one of the first numbers a review asks for." },
        ],
        decoys: [
          { line: 7, why: "'Landed in' for 'reached', 'for' for 'on': the same fact and the same timestamp. Wording isn't a finding." },
        ],
        hud: "Tap the lines with no evidence behind them, or that blame someone",
        sameLine: "That line matches the clean copy. The problem is elsewhere.",
        winTitle: "Draft marked up",
        howTo: [
          "The clean copy is on the left, the draft on the right.",
          "Tap a draft line that states something the evidence doesn't support, blames a person, or gives a time nobody can check.",
          "Different wording for the same fact is fine. A wrong tap costs a life.",
        ],
        lesson: "Each entry needs an exact time, exact facts and one sentence of consequence you could defend. Strong words don't add certainty, and a reviewer reads them as the first place to push.",
      },
      {
        kind: "tune",
        title: "How Much Detail Does the Engineer Get?",
        prompt: "Same incident, opposite reader. The engineer rebuilding remote access has to reproduce your reasoning, not take your word for it. Tune the red pen so it strikes what can't be rerun, and keeps six lines.",
        eventColumn: "Line for the technical sections",
        mode: "any",
        dials: [
          { id: "exact", label: "Strike if exact values are only", short: "Exact", dir: "below", min: 0, max: 5, step: 1, start: 3 },
          { id: "source", label: "Strike if evidence sources named are only", short: "Sources", dir: "below", min: 0, max: 2, step: 1, start: 1 },
        ],
        events: [
          { id: "b1", label: "Contact details of 1,180 parents and carers were copied out of the trust.", bad: true, values: { exact: 1, source: 0 } },
          { id: "k1", label: "Gateway auth log: 2026-10-26T21:47:12Z, ext.jkerr, 198.51.100.42, password only.", bad: false, values: { exact: 3, source: 1 } },
          { id: "b3", label: "The firewall shows a large transfer that night.", bad: true, values: { exact: 0, source: 1 } },
          { id: "k2", label: "DeviceNetworkEvents: rc.exe on BW-MIS02 to 203.0.113.58:443 at 2026-10-26T23:12:33Z.", bad: false, values: { exact: 4, source: 1 } },
          { id: "b7", label: "2026-10-26T23:12:33Z: rc.exe connected to 203.0.113.58:443.", bad: true, values: { exact: 3, source: 0 } },
          { id: "k6", label: "Firewall and EDR agree the transfer ended at 2026-10-26T23:19:07Z on BW-MIS02.", bad: false, values: { exact: 2, source: 2 } },
          { id: "b2", label: "The intruder's access ended on 28 October.", bad: true, values: { exact: 1, source: 0 } },
          { id: "k3", label: "Firewall log: 41 MB from BW-MIS02 to 203.0.113.58 on 2026-10-26.", bad: false, values: { exact: 4, source: 1 } },
          { id: "b4", label: "EDR telemetry shows a tool ran on BW-MIS02.", bad: true, values: { exact: 1, source: 1 } },
          { id: "k4", label: "Share audit event 5145 on BW-MIS02: ext.jkerr read \\\\BW-MIS02\\Exports.", bad: false, values: { exact: 4, source: 1 } },
          { id: "b5", label: "The gateway log shows a contractor account signed in.", bad: true, values: { exact: 0, source: 1 } },
          { id: "k5", label: "EDR timeline: C:\\Users\\Public\\Documents\\rc.exe first ran on BW-MIS02 at 2026-10-26T23:09:51Z.", bad: false, values: { exact: 3, source: 1 } },
          { id: "b6", label: "We are notifying the regulator and the affected families this week.", bad: true, values: { exact: 0, source: 0 } },
        ],
        goal: { catch: 7, maxFalse: 0 },
        deploys: 3,
        howTo: [
          "Exact counts the values someone could search for: timestamps, hosts, addresses, paths, accounts. Sources counts the log or tool the line names.",
          "The rule is the same red pen: it strikes a line when either dial trips. Set both dials, then press Deploy the rule.",
          "As before, an attack is a line that should go, and false is a line the engineer needs that you struck.",
        ],
        lesson: "Run the chair's pen here and it strikes all the evidence. Run this one over the summary and it strikes the summary. Neither reader is wrong, which is why one report holds both. A line with a precise value and no source still fails here: the engineer can see the claim but not how to check it.",
      },
    ],
    // ── Log analysis: from a raw record to the report ──
    "doc-la1": [
      {
        kind: "anatomy",
        title: "Read the Record Before You Quote It",
        prompt: "This is the record behind the transfer on BW-MIS02. Before any of it goes in the report, scan it field by field and see where each value ends up.",
        primer: {
          title: "From a record to a report line",
          points: [
            "A record's column names tell you what each value is. Each kind of IOC comes from the column that holds exactly that value.",
            "Copy values character for character, from the record and never from memory.",
            "A hash column's name gives its algorithm. Keep that label with the value.",
            "To cite a record, give the query that finds it, so another analyst can rerun it: scope to the device, then to the action.",
            "Both filter values come straight from the record, and `==` needs an exact match.",
          ],
          example: {
            label: "An evidence query (a museum's report)",
            lines: [
              "`DeviceEvents`",
              "`| where DeviceName == \"mus-db01.museum.example\"`",
              "`| where ActionType == \"UsbDriveMounted\"`",
              "`| project Timestamp, AccountName, AdditionalFields`",
            ],
          },
        },
        source: "Advanced Hunting · DeviceNetworkEvents · bw-mis02",
        fields: [
          { key: "Timestamp", value: "2026-10-26T23:12:33Z", label: "When", note: "Goes into the timeline as it stands, zone included." },
          { key: "DeviceName", value: "bw-mis02.bellwether.example", label: "Where", note: "The first filter of the evidence query." },
          { key: "ActionType", value: "ConnectionSuccess", label: "What happened", note: "The second filter. A connection that completed, which is more than an attempt." },
          { key: "RemoteIP", value: "203.0.113.58", label: "To where", note: "One atomic value, ready for the IOC list." },
          { key: "RemotePort", value: "443" },
          { key: "RemoteUrl", value: "files.quickdrop.example", label: "Domain", note: "Another IOC line, exactly as recorded." },
          { key: "InitiatingProcessFileName", value: "rc.exe", label: "What connected" },
          { key: "InitiatingProcessFolderPath", value: "C:\\Users\\Public\\Documents\\rc.exe", label: "Full path", note: "FolderPath columns include the file name. This is the file-path IOC." },
          { key: "InitiatingProcessSHA256", value: "7be1c04fa93d52e816cd04b7f3a96e21d85c40f7ab12e693c7d0158ea46fb3d9", label: "Hash", note: "The column name carries the algorithm. Write SHA256 beside the value when it goes in the report." },
        ],
        summary: "One record feeds three sections. Its time and action become a timeline entry with one sentence of consequence. Its atomic values go in the IOC list. The query that found it, and who pulled it and when, go in Evidence Sources & Analysis, so another analyst can repeat the path.",
      },
    ],
    // ── Reading 4: defensibility ──
    "doc-r4": [
      {
        kind: "intercept",
        title: "Will This Claim Stand?",
        prompt: "A reviewer from the trust's insurer reads the Bellwether report next month. Every claim below is about to go in. Keep the ones that would survive questioning, and send the rest back to the writer.",
        protect: "the report's credibility",
        blockLabel: "Send back",
        passLabel: "Keep",
        seconds: 13,
        primer: {
          title: "What makes a report defensible",
          points: [
            "**Defensible** means the facts survive being questioned later, by a manager, an auditor, a lawyer or your own team. The saying is: if it wasn't documented, it didn't happen.",
            "Write as each fact is established. A reviewer can read what you wrote at the time, and that's all they can read.",
            "Every claim answers six questions: **who, what, when, where, why it matters, and how you know**.",
            "**Chain of custody:** each cited item says where it came from, when it was pulled and by whom.",
            "Say what you didn't check. State what was searched, over what period, and where the search stopped.",
          ],
          example: {
            label: "One claim, weak and strong (a museum's report)",
            lines: [
              "Weak: `We found a bad file on the server.`",
              "Strong: `The SHA256 value came from a DeviceFileEvents record on MUS-DB01, pulled 2026-02-12 by a.noor.`",
            ],
          },
        },
        items: [
          { id: "c1", text: "rc.exe's SHA256 came from DeviceNetworkEvents on BW-MIS02, pulled 2026-10-28 by m.adeyemi.", sub: "Evidence section", bad: false, why: "Where it came from, when it was pulled, and by whom." },
          { id: "c2", text: "We found a suspicious program on a server.", sub: "Evidence section", bad: true, why: "Which program, which server, when, found how? A reviewer has to come back and ask all of it." },
          { id: "c3", text: "No sign-in from 198.51.100.42 appeared on the MFA gateway in the 30 days of logs reviewed.", sub: "Technical Timeline", bad: false, why: "It names what was searched and how far back, so the claim is exactly as wide as the work." },
          { id: "c4", text: "The intruder never went near any other school.", sub: "Executive Summary", bad: true, why: "Nobody searched everything. Say which logs were checked and how far back." },
          { id: "c5", text: "Gateway logs before 2026-09-26 had rolled off and were not examined.", sub: "Evidence section", bad: false, why: "It reads like an admission and works like a strength. A report that states its edges earns more trust, because nobody finds them later." },
          { id: "c6", text: "As far as I remember, the transfer had stopped before midnight.", sub: "Technical Timeline", bad: true, why: "The record has an exact time. Quote it, and cite it." },
          { id: "c7", text: "Firewall log exported 2026-10-28T09:15Z by l.osei: 41 MB from BW-MIS02 to 203.0.113.58.", sub: "Evidence section", bad: false, why: "Source, pull time, person, and the exact finding." },
          { id: "c8", text: "All parents were affected.", sub: "Executive Summary, while the Affected Systems section lists 1,180", bad: true, why: "The summary claims more than the section beneath it supports, and a skeptical reader finds that gap first. It then costs trust in everything else." },
          { id: "c9", text: "The contractor's laptop was probably infected.", sub: "Technical Timeline. Nobody examined the laptop", bad: true, why: "A guess about something never looked at. Say the laptop wasn't examined, and leave it there." },
          { id: "c10", text: "Case note, 2026-10-28T09:13Z, p.hale: BW-MIS02 stays up until memory is captured, to keep the running process.", sub: "Evidence section", bad: false, why: "A decision with its time, its owner and its reason, written when it was made." },
        ],
        lesson: "A claim stands when it can say who, what, when, where, why it matters and how you know, and when it claims no more than was checked. If the summary and the technical section disagree, a reviewer stops trusting both.",
      },
      {
        kind: "worksheet",
        title: "Which Decision Can Nobody Prove?",
        prompt: "This is the decision log from the Wednesday of the Bellwether response. A governor has started asking why parents couldn't log in that afternoon. Read the log and answer.",
        caption: "Decision log · BW-INC-0417 · 2026-10-28 and 2026-10-29",
        columns: ["Decided (UTC)", "Decision", "By", "Written down"],
        rows: [
          ["10-28 09:12", "Keep BW-MIS02 up until memory is captured", "p.hale", "10-28 09:13, case notes"],
          ["10-28 09:38", "Disable ext.jkerr and shut down BW-RAS01", "p.hale", "10-28 09:41, case notes"],
          ["10-28 11:20", "Tell the 14 head teachers by phone, not email", "p.hale", "10-28 11:26, case notes"],
          ["10-28, time unknown", "Pause parent portal logins for the afternoon", "not recorded", "11-02, from memory"],
          ["10-29 15:40", "Move remote access to the MFA gateway", "a.brennan", "10-29 15:42, case notes"],
        ],
        questions: [
          { id: "which", q: "Which system's decision could a reviewer not verify?", hint: "Read the By and Written down columns, not the Decision column.", answer: ["parent portal", "portal", "the parent portal"], why: "No time, no name, and written days later. Every other row lets a reviewer check who decided, when and at what moment it was noted. This one gives them nothing to check." },
          { id: "days", q: "How many days after the decision was that entry written?", hint: "From the 28th of October to the 2nd of November.", answer: ["5", "five"], why: "Five days. By then it can't be told apart from a story someone has settled on since." },
          { id: "mins", q: "How many minutes passed between the decision to disable ext.jkerr and its note?", hint: "Decided against Written down, same row.", answer: ["3", "three"], why: "Three minutes. That is writing as you go, and it's how the other four entries can answer a question asked months later." },
        ],
      },
    ],
    // ── Analyst choice: what stays out of the findings ──
    "doc-ac1": [
      {
        kind: "queue",
        title: "Does It Go in the Report?",
        prompt: "Four more alerts from incident week sit beside the case, and some touch the same servers. Priyanka wants each one checked before the report names it. Open each one and give it a verdict.",
        console: "SIEM · BW-INC-0417 · related alerts",
        primer: {
          title: "Check it before it goes in",
          points: [
            "A **true positive** is a correct detection of real malicious activity.",
            "A **benign true positive** is a correct detection of real activity that turned out to be authorised.",
            "A **false positive** is a detection that was simply wrong: what it reported didn't happen.",
            "Timing proves nothing on its own. Verify a candidate before it goes anywhere near the IOC list: a change ticket must match the who, the where and the when.",
            "Cleared activity stays out of the findings. Record the ticket, so a reviewer sees it was checked.",
          ],
          example: {
            label: "Checking a candidate (a museum's report)",
            lines: [
              "Alert: `archive job read 40,000 files on MUS-FS02 on a Sunday`",
              "Ticket CHG-118 names that job, that server, that Sunday. All three match, so it's verified.",
            ],
          },
        },
        actions: [
          { id: "tp", label: "True positive: report it", tone: "escalate" },
          { id: "btp", label: "Benign true positive: record the check", tone: "close" },
          { id: "fp", label: "False positive: record the check", tone: "close" },
        ],
        alerts: [
          {
            id: "a1", time: "10-27 02:10", severity: "High", rule: "Mass read of a file share", entity: "BW-MIS02",
            fields: [{ k: "Account", v: "svc-nightly" }, { k: "Share", v: "\\\\BW-MIS02\\Exports" }, { k: "Files read", v: "18,204" }, { k: "Source", v: "10.40.2.5 (backup server)" }],
            context: "Same share the intruder read, the night after. CHG-5120 names this job, this share and a nightly 01:00 to 04:00 window. The backup system's log shows the run.",
            answer: "btp",
            why: "It's real and the rule was right to fire, and the ticket matches the who, where and when. The same share on the next night is a coincidence you can now prove.",
          },
          {
            id: "a2", time: "10-26 22:03", severity: "Medium", rule: "SMB share enumeration", entity: "BW-FS03",
            fields: [{ k: "Source", v: "10.40.8.21 (gateway pool)" }, { k: "Account", v: "ext.jkerr" }, { k: "Linked ticket", v: "CHG-5098" }],
            context: "CHG-5098 was linked automatically because it contains the word 'scan'. It covers BW-PRN01, on 2026-10-14. IT had nothing planned for this night.",
            answer: "tp",
            why: "A ticket was attached, and it matches nothing: another server, two weeks earlier. A link isn't verification. This stays in as a finding.",
          },
          {
            id: "a3", time: "10-27 10:44", severity: "High", rule: "File hash matched threat feed", entity: "BW-LIB03",
            fields: [{ k: "File", v: "LibraryDesk.exe" }, { k: "Signature", v: "Valid, the library software's publisher" }, { k: "Feed entry", v: "First 8 characters of a hash" }],
            context: "The feed entry was cut short on import, so the rule matched a prefix. The file's full SHA256 differs from the one the feed published.",
            answer: "fp",
            why: "The detection was wrong: this file isn't the one on the feed. In a benign true positive, by contrast, the event is real and authorised.",
          },
          {
            id: "a4", time: "10-27 20:06", severity: "Medium", rule: "Port scan across internal hosts", entity: "BW-MIS02",
            fields: [{ k: "Source", v: "10.40.2.9 (vulnerability scanner)" }, { k: "Hosts probed", v: "312" }, { k: "Ticket", v: "CHG-5104" }],
            context: "CHG-5104 is the weekly scan: this scanner, all internal subnets, Tuesdays 20:00 to 23:00. It ran on time and finished on time.",
            answer: "btp",
            why: "A port scan in incident week looks alarming, and the ticket covers exactly this source, these hosts and this window. Real, detected and authorised.",
          },
        ],
      },
    ],
    // ── Reading 5: root cause and recommendations ──
    "doc-r5": [
      {
        kind: "spotdiff",
        title: "Mark Up the Root Cause",
        prompt: "This is the last section before the Bellwether report goes for sign-off, and an earlier draft got passed round by mistake. Tap each draft line that retells the attack, blames a person, guesses, or names nothing anyone could fix.",
        primer: {
          title: "A cause, not a retelling",
          points: [
            "A root cause says what **allowed** the intrusion to succeed: which control was missing, misconfigured or not enforced, and where relevant why that gap existed.",
            "A sentence that describes what the attacker did belongs in the timeline. It gives the fixes nothing to work with.",
            "A sentence that puts it on a person changes nothing: the next person walks into the same hole. Ask which control should have held.",
            "Test: could an owner take this sentence and know what to change?",
          ],
          example: {
            label: "Three versions of one cause (a museum's report)",
            lines: [
              "Retelling: `The intruder logged in to the collections database over RDP.`",
              "Blame: `The volunteer should have known better.`",
              "Gap: `RDP on MUS-DB01 was reachable from visitor Wi-Fi, because the 2024 network split never reached that building.`",
            ],
          },
        },
        goodTitle: "Signed-off copy (p.hale)",
        suspectTitle: "Earlier draft",
        good: [
          "ROOT CAUSE",
          "BW-RAS01 was left out of the spring MFA rollout because it was due to retire.",
          "The retirement slipped to 2027 and nobody reopened the exception.",
          "ext.jkerr stayed enabled five months after the contract ended.",
          "The leavers process runs from HR records, and agency contractors aren't in them.",
          "How the password left the contractor has not been established.",
          "RECOMMENDATIONS",
          "Keep BW-RAS01 retired. Owner: a.brennan. Done 2026-10-29.",
          "Require MFA on every remote route, and give each exception an expiry date. Owner: IT director. Due 2026-12-01.",
          "Bring agency contractors into the leavers process. Owner: HR lead. Due 2026-11-20.",
        ],
        suspect: [
          "ROOT CAUSE",
          "An intruder signed in to BW-RAS01 and copied the exports.",
          "The retirement slipped to 2027, and nobody reopened the exception.",
          "The contractor failed to look after a password.",
          "The leavers process runs from HR records, and agency contractors aren't in them.",
          "The password was almost certainly phished.",
          "RECOMMENDATIONS",
          "Keep BW-RAS01 retired. Owner: a.brennan. Done 2026-10-29.",
          "Strengthen the trust's overall security posture.",
          "Bring agency contractors into the leavers process. Owner: HR lead. Due 2026-11-20.",
        ],
        diffs: [
          { line: 1, why: "That's the timeline again. It says what the intruder did and nothing about why it worked." },
          { line: 3, why: "Blame. Swap in any other contractor and the same thing happens, because the account should not have been live at all." },
          { line: 5, why: "A guess in the voice of a finding. Nothing shows how the password left, and saying so plainly is stronger." },
          { line: 8, why: "Nobody can own this line, and nobody could ever check that it was done. It replaced the action that closes the MFA gap." },
        ],
        decoys: [
          { line: 2, why: "One comma. The same fact, and a true gap." },
        ],
        hud: "Tap the lines that retell, blame, guess or fix nothing",
        sameLine: "That line matches the signed-off copy. Look elsewhere.",
        winTitle: "Draft marked up",
        howTo: [
          "The signed-off copy is on the left, the earlier draft on the right.",
          "Tap a draft line that retells the attack, blames a person, guesses, or names nothing fixable.",
          "A small wording change isn't a fault. A wrong tap costs a life.",
        ],
        lesson: "A good cause points at a control and says why it wasn't there. Here that's an exception nobody revisited and a process that never covered contractors. Both have owners, and both can be checked next term.",
      },
      {
        kind: "sort",
        title: "Which Gap Does It Close?",
        prompt: "Staff have sent in suggestions for the Recommendations section. The Root Cause names two gaps: the gateway left out of MFA, and contractor accounts outside the leavers process. Sort each suggestion by the gap it closes.",
        primer: {
          title: "One gap, one action",
          points: [
            "Each recommendation points back at a gap the Root Cause names.",
            "It says exactly what changes, an owner can take it, and someone can check later that it was done.",
            "A line that points at no named gap has no place here, however sensible it sounds.",
          ],
          example: {
            label: "From gap to action (a museum's report)",
            lines: [
              "Gap: `RDP on MUS-DB01 is reachable from visitor Wi-Fi.`",
              "Action: `Move MUS-DB01 behind the staff network. Owner: network lead. Check: a scan from visitor Wi-Fi reaches nothing.`",
            ],
          },
        },
        buckets: [
          { id: "mfa", label: "Closes the MFA gap" },
          { id: "leavers", label: "Closes the leavers gap" },
          { id: "neither", label: "Traces to neither" },
        ],
        items: [
          { id: "r1", text: "Block sign-in on any remote route that can't enforce MFA.", bucket: "mfa", why: "It goes straight at how one password was enough." },
          { id: "r2", text: "Keep a register of MFA exceptions, each with an expiry date and a named owner.", bucket: "mfa", why: "The exception was never revisited. An expiry date makes someone revisit it." },
          { id: "r3", text: "Alert the IT director when an MFA exception passes its expiry date.", bucket: "mfa", why: "This catches the next slipped retirement before an intruder does." },
          { id: "r4", text: "Add agency contractors to the HR leavers process.", bucket: "leavers", why: "They weren't in it, so nothing ever triggered the disable." },
          { id: "r5", text: "Disable ext. accounts automatically on the contract end date.", bucket: "leavers", why: "The account was live for five months after the work ended. This removes that window." },
          { id: "r6", text: "Review every enabled ext. account with the agency each month.", bucket: "leavers", why: "A checkable control for the same gap, which also finds any accounts already missed." },
          { id: "r7", text: "Build a stronger security culture across the trust.", bucket: "neither", why: "It sounds fine and changes nothing that failed here." },
          { id: "r8", text: "Subscribe to a threat intelligence feed.", bucket: "neither", why: "It might be useful one day. It wouldn't have stopped one valid password on an old gateway." },
          { id: "r9", text: "Encrypt all staff laptops.", bucket: "neither", why: "A good idea with no link to this incident. Nothing in this incident turned on a lost device." },
        ],
      },
    ],
    // ── The boss: write it yourself ──
    "doc-wr1": [
      {
        kind: "worksheet",
        title: "What Earns the Marks",
        prompt: "Your write-up is marked by a fixed scheme. Priyanka has run four practice write-ups through it, all on one practice case. Read the marking sheet and answer, so you know what yours has to do.",
        primer: {
          title: "How this write-up is marked",
          points: [
            "Two parts. An **Executive Summary** of 3 to 6 sentences, stating what happened, the scope, the current status and the impact in plain business language, with no ATT&CK IDs and no field names. Then a **Root Cause** that names the control gap.",
            "**Length counts.** At least 60 words, and around 90 earns full marks for depth.",
            "**Evidence counts for more.** Every real identifier from the case that you copy exactly earns marks: the host, the account, the task name, the hash. Two is the least that can pass. All four scores best. The Root Cause is the natural place for them.",
            "**Never invent a value.** An IP, hash or email address that appears nowhere in the case counts as made up, and it wipes out nearly all the evidence marks. Values from this room's practice labs are Bellwether's, so they count as made up too.",
            "**Where to find the case's facts.** Open Field notes on Reading 1 for the current status and impact, and on Reading 5 for the control gap. The hash is in the record from the task From Raw Log to Report.",
          ],
          example: {
            label: "A write-up that would pass (a clinic's mailbox, about 90 words)",
            lines: [
              "`Executive Summary: An intruder read a receptionist's mailbox for two days using a stolen password. Appointment details for about 300 patients were within reach, and we have found no sign they were copied. Access was cut on Tuesday and the password has been replaced. We are reviewing whether patients need to be told, and will decide this week.`",
              "`Root Cause: Mailbox r.dale on HS-MX01 had no second sign-in check, because the front-desk group was excluded from the sign-in policy after a 2025 printer fault and nobody reviewed that exclusion when the fault was fixed.`",
            ],
          },
        },
        caption: "Marking sheet · four practice write-ups · 4 identifiers were available in the case",
        columns: ["Write-up", "Words", "Real identifiers, copied exactly", "Invented values"],
        rows: [
          ["A", "95", "1", "0"],
          ["B", "110", "4", "1"],
          ["C", "72", "2", "0"],
          ["D", "95", "3", "0"],
        ],
        questions: [
          { id: "top", q: "Which write-up scores highest?", hint: "Look for a good length, as many exact identifiers as possible, and nothing invented.", answer: ["D", "write-up d"], why: "Full marks for length, three exact identifiers, nothing made up." },
          { id: "inv", q: "Write-up B cites all four identifiers. Does it pass? (yes/no)", hint: "Check the last column.", answer: ["no"], why: "One invented value wipes out nearly all the evidence marks, however much else is real. Leaving a value out always costs less than making one up." },
          { id: "one", q: "Write-up A is long and invents nothing. Does it pass? (yes/no)", hint: "Check the identifiers column against the least that can pass.", answer: ["no"], why: "One identifier isn't enough, however good the prose. The writing has to be tied to the case's own evidence." },
          { id: "low", q: "Which is the weakest write-up that still passes?", hint: "Two identifiers, enough words, nothing invented.", answer: ["C", "write-up c"], why: "It clears the word minimum and cites two exact identifiers. More of either would earn more." },
        ],
      },
      {
        kind: "spotdiff",
        title: "Mark Up the Final Draft",
        prompt: "Your last job before your own. This is the Bellwether Executive Summary and Root Cause on its way to the chair. Priyanka's clean copy is on the left. Tap each draft line that overclaims, blames someone, or only retells the attack.",
        goodTitle: "Clean copy (p.hale)",
        suspectTitle: "Draft for the chair",
        good: [
          "EXECUTIVE SUMMARY",
          "An intruder used a contractor's password to get in through our old remote-access service.",
          "Contact details of 1,180 parents and carers were copied out of the trust.",
          "Pupil attendance records at three schools were reachable; we found no sign they were copied.",
          "The intruder's access ended on 28 October and the old service has been switched off.",
          "We are notifying the regulator and the affected families this week.",
          "ROOT CAUSE",
          "BW-RAS01 sat outside the MFA rollout because it was due to retire, and that exception was never revisited.",
          "ext.jkerr stayed enabled after the contract ended, because agency contractors are outside the leavers process.",
          "So one password was enough to reach BW-MIS02, with no second check.",
          "How the password left the contractor has not been established.",
        ],
        suspect: [
          "EXECUTIVE SUMMARY",
          "An intruder got in through our old remote-access service using a contractor's password.",
          "Contact details of 1,180 parents and carers were copied out of the trust.",
          "No pupil records were touched.",
          "The intruder has gone for good and the trust is now fully secure.",
          "We are notifying the regulator and the affected families this week.",
          "ROOT CAUSE",
          "BW-RAS01 sat outside the MFA rollout because it was due to retire, and that exception was never revisited.",
          "The contractor's carelessness caused this incident.",
          "The intruder then moved to BW-MIS02 and copied the exports.",
          "How the password left the contractor has not been established.",
        ],
        diffs: [
          { line: 3, why: "The evidence says reachable, with no sign of copying. 'Not touched' claims more than anyone checked, in the sentence a chair will repeat." },
          { line: 4, why: "A promise no report can make. Say when access ended and what was shut down." },
          { line: 8, why: "Blame again, with no gap to fix. The real sentence names the process that never covered contractors." },
          { line: 9, why: "A retelling in the Root Cause. What the intruder did next is the timeline's job. Here the point is why a single password was enough." },
        ],
        decoys: [
          { line: 1, why: "The clauses swapped round, with the same fact in plain words. Leave it." },
        ],
        hud: "Tap the lines that overclaim, blame or only retell",
        sameLine: "That line matches the clean copy. Look elsewhere.",
        winTitle: "Ready for the chair",
        howTo: [
          "The clean copy is on the left, the draft on the right.",
          "Tap a draft line that claims more than the evidence shows, blames a person, or retells the attack where a gap should be named.",
          "A reworded line with the same meaning is fine. A wrong tap costs a life.",
        ],
        lesson: "That's the whole room in eleven lines. The summary is translated and claims only what was checked. The cause names a control and why it failed. Now write yours on the Solstice case, in your own words, using its own evidence.",
      },
    ],
  },
};
