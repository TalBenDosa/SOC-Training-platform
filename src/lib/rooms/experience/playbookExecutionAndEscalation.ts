import type { RoomExperience } from "./types";

// "Operation Runbook" for the "playbook-execution-and-escalation" room.
// Script: docs/campaign/86-playbook-execution-and-escalation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Greenhithe Foods Distribution (fictional), not the graded tasks' Northvale records.
// Signature: When the Page Doesn't Match. The learner runs a written page step by step (simulate),
// spots the line where reality stopped matching and picks the note that records why (trace), then
// chooses the branch that applies (defuse). A playbook is a floor, not a ceiling, and a skipped step
// needs a recorded reason. Room 66 covers automated playbooks; this one is the human running the page.
// Game mix: codebreak + defuse + intercept + rush.
// Task order unchanged. The boss holds ac1 and the three tasks that can only follow it.
//
// Lab data differs from the graded tasks. The page is PB-22, malware on one workstation, never
// IR-014 or a compromised account. The scope gate breaks on a file hash across devices in a software
// push, not on one source signing in as several people (la2, ac1). The sign-in record is blocked by
// Conditional Access, ResultType 53000, status failure, with MFA required, not ResultType 0 and
// notApplied on a password alone (la1). The silent hits are devices judged per device, not sign-ins
// judged per user (la2). The failure-history lab is a haulier portal over 30 days (la2). What a fix
// leaves behind is a scheduled task, a Run key, a second domain and a remote tool, never a password
// reset, a mailbox rule or an app consent (q1). "Done or ticked" uses PB-22 steps (m1). The page-out
// is five lines about devices (r3, q2). No lab shows a Northvale value, name or address.

export const PLAYBOOK_EXECUTION_AND_ESCALATION: RoomExperience = {
  roomId: "playbook-execution-and-escalation",
  codename: "Operation Runbook",
  theme: "runbook",
  handler: { name: "Sanaa Kowalczyk", role: "IR Coordinator, Greenhithe Foods Distribution" },
  briefing: [
    "Greenhithe Foods Distribution. Three depots, 430 staff, and chilled food on the road to 1,100 shops before their doors open.",
    "Loading starts at 02:00, and the red ring binder on the SOC desk has a page for most things that can go wrong before then.",
    "Tonight one alert came in on one dispatch PC, and the page for it is clear. Sanaa Kowalczyk wrote that page, and is the first to say a page can be wrong.",
    "Run it properly, notice when what's in front of you stops matching the paper, step off with a reason, and make the call.",
  ],
  mission: "Learn what a page assumes, walk it until reality stops matching, read a sign-in record field by field, search the other way round, count what really belongs in scope, pick the branch that applies, then write the record that makes stepping off stand up.",
  estimate: "~50 min",
  look: { primary: "#e6c229", secondary: "#4fd1c5", warn: "#f25c54" },
  scene: "facilityrunbook",
  layout: "facility",
  stations: [
    {
      id: "binder",
      label: "The Binder",
      topic: "What a playbook is for · The situation it assumes · Why the steps run in this order",
      tagline: "Written in March. Used tonight.",
      building: "archive",
      taskIds: ["pbk-r1", "pbk-o1"],
    },
    {
      id: "walk",
      label: "Walk the Page",
      topic: "The scope gate · Stepping off with a reason · Validating a sign-in · What each step produces",
      tagline: "Every step, in order, eyes open",
      building: "office",
      taskIds: ["pbk-r2", "pbk-la1", "pbk-q1", "pbk-m1"],
    },
    {
      id: "otherway",
      label: "The Other Way Round",
      topic: "Pivoting on the source · Why the queue undercounts · Reading what came before a success",
      tagline: "The ticket names one. Who else matches?",
      building: "lab",
      taskIds: ["pbk-la2"],
    },
    {
      id: "call",
      label: "The Call",
      topic: "Choosing the branch · Recording a step-off · A good escalation · How a ticket improves a page",
      tagline: "One action from a closed ticket",
      building: "control",
      taskIds: ["pbk-ac1", "pbk-q2", "pbk-r3", "pbk-f1"],
      boss: true,
    },
  ],
  personas: {
    "pbk-o1": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "This one's from Northvale's binder, a case I keep for training. Put it in running order." },
    "pbk-la1": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "Northvale's ticket, 03:10. Start where the page starts." },
    "pbk-q1": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "A colleague has opinions about your ticket. They usually do." },
    "pbk-m1": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "Tell me what each step leaves behind." },
    "pbk-la2": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "Read this record beside the first one." },
    "pbk-ac1": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "03:52, and the page is open in front of you. Your call." },
    "pbk-q2": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "Six months from now, someone reads this ticket. What do they need?" },
    "pbk-f1": { name: "Sanaa Kowalczyk", role: "IR Coordinator", line: "One number for the ticket. Read it off the records." },
  },
  briefings: {
    // ── Reading 1: what a page is, and why its order matters ──
    "pbk-r1": [
      {
        kind: "inspect",
        title: "What a Page Says Before Step 1",
        prompt: "This is the front of PB-22 in Greenhithe's binder, the page tonight's alert will send you to. Tap every line and read what it's there for. One of them decides whether the rest of the page applies at all.",
        artifact: "The Binder · PB-22 · front of page",
        items: [
          { id: "title", text: "PB-22: Malware on one workstation", tag: "Trigger", tone: "info", note: "A playbook is a written procedure for one kind of alert: what to do, in what order, with what evidence. Greenhithe's are numbered pages in a red ring binder, with a copy on the wiki." },
          { id: "covers", text: "Covers: one Windows workstation, one user, commodity malware.", tag: "Assumption", tone: "warn", note: "This is the picture in the author's head, and every step inherits it. Isolate which PC? This one. Sanaa wrote it in March, and March can't see tonight." },
          { id: "who", text: "For: whoever holds the pager.", tag: "Consistency", tone: "trust", note: "A tired analyst at 03:00 on a Sunday and the shift lead at 14:00 on a Tuesday run the same steps. That's the first reason a page exists." },
          { id: "evidence", text: "Each step lists the evidence it must leave in the ticket.", tag: "Completeness", tone: "trust", note: "Under pressure, collection is what people drop, because it feels like delay. A checklist doesn't get tired, and it doesn't decide it already knows this one." },
          { id: "record", text: "Record who ran each step, and when.", tag: "Defensibility", tone: "trust", note: "Six months from now someone asks why a PC was wiped. The answer should be a procedure and a record, not one person's memory." },
          { id: "owner", text: "Owner: S. Kowalczyk. Last reviewed: March 2026.", tag: "Age", tone: "warn", note: "A page is a snapshot. Tools get retired and hosts change jobs. The date tells you how old the snapshot is." },
          { id: "exit", text: "If this page stops fitting: stop, and page the IR Coordinator.", tag: "Exit line", tone: "info", note: "IR is Incident Response. The author knew the page might be wrong for some night they couldn't picture, and wrote down what to do then. Remember this line." },
        ],
      },
      {
        kind: "rush",
        title: "Read-Only or Changes Something?",
        prompt: "Sanaa's first test for anyone going on nights. These are the things people reach for in the first minutes of an alert on a PC. Call each one before you touch anything.",
        primer: {
          title: "Why order matters on a page",
          points: [
            "**Read-only** actions look at something and leave it as it was. You can repeat them and lose nothing.",
            "**State changes** alter the host, the network or an account. Many can't be undone.",
            "Each change destroys some evidence you haven't collected yet, and it tells an intruder you've seen them.",
            "You also can't size a response you haven't measured, so the change comes after the measuring.",
            "**EDR** (Endpoint Detection and Response) is the agent and console that records and acts on what happens on a PC.",
          ],
          example: {
            label: "The test, in the cold store",
            lines: [
              "Read the probe log for bay 4. **What's different afterwards?** Nothing. Read-only.",
              "Move the pallets to bay 6. **What's different afterwards?** The bay, the stock and the temperature record. A change.",
              "So the log comes first: once the pallets have moved, it can't tell you what happened to them.",
            ],
          },
        },
        trueLabel: "Read-only",
        falseLabel: "Changes something",
        seconds: 60,
        target: 10,
        cards: [
          { id: "c1", text: "Export the process tree from the EDR console", answer: true, why: "A copy of what the agent already recorded. The PC doesn't change." },
          { id: "c2", text: "Isolate the PC from the network", answer: false, why: "The right move later, but it's a change: the live traffic you could have watched stops, and whoever is on the other end sees it stop." },
          { id: "c3", text: "Kill the suspicious process", answer: false, why: "That process's memory goes with it, and the operator sees the session die." },
          { id: "c4", text: "Search the fleet for the file's hash", answer: true, why: "A query over telemetry. Nothing on any device is touched." },
          { id: "c5", text: "Reboot the PC to clear the pop-up", answer: false, why: "Everything in RAM is gone: running code, connections, keys." },
          { id: "c6", text: "Read the proxy log for that PC", answer: true, why: "The log sits on another system, and reading it changes nothing." },
          { id: "c7", text: "Delete the scheduled task you found", answer: false, why: "It's gone before you've recorded it, and its absence is a signal to the intruder." },
          { id: "c8", text: "Check the alert isn't a duplicate of a closed one", answer: true, why: "Asking whether it's real costs nothing, and it comes before everything else." },
          { id: "c9", text: "Block the domain at the firewall", answer: false, why: "A sensible control, later. Done now, it tells the operator you've noticed." },
          { id: "c10", text: "List open connections in a remote session", answer: true, why: "The Live Response command connections reports what's there. Nothing is altered in any way that matters." },
          { id: "c11", text: "Ask the user to open the file again", answer: false, why: "That runs it a second time on a PC you're still measuring." },
          { id: "c12", text: "Read the file's signer in the console", answer: true, why: "The agent already holds this. You're only looking at it." },
          { id: "c13", text: "Rename the file so it can't run", answer: false, why: "You've changed the evidence, and the timestamps along with it." },
          { id: "c14", text: "Pull the EDR's investigation package", answer: true, why: "It gathers logs and artefacts into a copy for you. It's built to be run before you change anything." },
        ],
        lesson: "Read-only work can happen as often as you like. Every change costs evidence and tells someone you've seen them, so changes wait until you know the alert is real, what's there, and how far it goes. That's why a page runs in the order it does.",
      },
    ],
    // ── Reading 2: the scope gate ──
    "pbk-r2": [
      {
        kind: "simulate",
        title: "When the Page Doesn't Match",
        prompt: "Four tickets that ran on PB-22 this week, and the last one is still open in front of you. Pick a ticket, read its line, and say to yourself which step will break before the run shows you. Green means the page still fits what's there. Red means it has stopped fitting.",
        primer: {
          title: "Reading a page against what's in front of you",
          points: [
            "Every page has a **scope condition**: the situation its author pictured. Every step inherits it.",
            "The **scope gate** is the step that tests it: is tonight still the situation this page was written for?",
            "To test it, search on the event's own properties across the whole fleet, such as a file's **SHA256** hash (a fingerprint of its contents) or a domain. That's a **pivot**. A search on the name in the ticket can only return that name.",
            "Any line of a page can stop fitting: a tool gets retired, a PC has a second job nobody wrote down.",
            "A page is a **floor, not a ceiling**. Do at least what it says, and when it stops matching what's there, step off and record why.",
          ],
          example: {
            label: "The method, on a cold-store alarm",
            lines: [
              "Procedure CS-3 assumes: a door left open on one bay.",
              "Step 1, read the probe: bay 4 is warm. The procedure fits.",
              "Step 2, check the door: it's shut. The procedure no longer fits.",
              "Step 3 says close the door. There's nothing to close, so you stop, call refrigeration, and the log says why.",
            ],
          },
        },
        checks: [
          { name: "1 Confirm", question: "The page assumes a real detection on a real file." },
          { name: "2 Capture", question: "The page assumes the capture tool it names is there." },
          { name: "3 Measure", question: "The page assumes a fleet search finds one workstation." },
          { name: "4 Isolate and rebuild", question: "The page assumes a desk PC that can drop off the network." },
          { name: "5 Hand back", question: "The page assumes the case ends with this PC." },
        ],
        scenarios: [
          {
            id: "mon",
            label: "GFD-INC-3290, Monday",
            detail: "GFD-STOCK-02, Stock Control. Adware bundled with a free PDF tool. One alert.",
            results: ["pass", "pass", "pass", "pass", "pass"],
            why: [
              "Real file, real detection, not a duplicate.",
              "CollectKit ran from the IT share before anything changed.",
              "Fleet search on the hash and the domain: GFD-STOCK-02 and nothing else.",
              "Isolated, cleaned, rebuilt.",
              "Back with Stock Control, line manager told, summary written.",
            ],
            verdict: "The page fits from top to bottom, which is most weeks. Finishing a page that fits is a full result. You still checked at Step 3, and that's why you know it fits.",
          },
          {
            id: "tool",
            label: "GFD-INC-3301, Tuesday",
            detail: "GFD-TRANS-06, Transport. A trojan in a fake invoice. One alert. Overnight, GFD-IT01 was decommissioned, and CollectKit lived on it.",
            results: ["pass", "fail", "pass", "pass", "pass"],
            why: [
              "Real file, real detection.",
              "The tool on the page has gone. The step's purpose hasn't: evidence before change. The EDR's Collect investigation package gathers the same things.",
              "Fleet search: GFD-TRANS-06 only. The page fits again.",
              "Isolated, cleaned, rebuilt.",
              "Handed back and closed.",
            ],
            verdict: "Step off one line and carry on. The ticket says: Step 2, CollectKit gone with GFD-IT01, used Collect investigation package, 14:12. Swapping tools silently would leave the next reader unsure what evidence exists. Sanaa reissued the line that afternoon, because the ticket said so.",
          },
          {
            id: "cold",
            label: "GFD-INC-3307, Wednesday",
            detail: "GFD-CSTORE-02, North depot. An info-stealer from a fake browser update. One alert. This PC also drives the cold-store temperature alarms.",
            results: ["pass", "pass", "pass", "fail", "pass"],
            why: [
              "Real file, real detection.",
              "Package collected, nothing changed.",
              "Fleet search: this PC only.",
              "Isolation would cut the alarms on the freezer bays, and the food-safety record with them. The page pictured a desk PC. Nobody told it this one has a second job.",
              "Back in service, with a note on the asset record.",
            ],
            verdict: "Step off at Step 4, and not before. Hold the isolation, block the domain, page Sanaa, and isolate once somebody at the depot is reading the probes by hand. The ticket says why Step 4 ran late. The page wasn't wrong about the malware. It didn't know what the PC does.",
          },
          {
            id: "tonight",
            label: "GFD-INC-3318, tonight",
            detail: "GFD-DISP-07, Dispatch, South depot. An unsigned rtplan_update.exe, flagged at 22:40. One alert, loading starts at 02:00, and Step 4 is one click away.",
            results: ["pass", "pass", "fail", "fail", "fail"],
            why: [
              "File on disk, no duplicate, detection holds.",
              "Package collected, nothing changed.",
              "The page pictures one workstation. The fleet search on the file's SHA256 returns five devices, and the queue only ever showed one. This is the one step that could have told you.",
              "Not run. Rebuilding one of five leaves four, and closes the ticket.",
              "Not run. There's nothing to hand back while the case is open.",
            ],
            verdict: "Stop at Step 3. This isn't a bad run of PB-22: the last line of the page sends you to the IR Coordinator when it stops fitting. The steps you didn't run stay visibly unticked and the ticket stays open, and that's the accurate state of things.",
          },
        ],
      },
      {
        kind: "trace",
        title: "Spot the Line, Give the Reason",
        prompt: "Now you do the spotting. Two closed tickets from Sanaa's review pile, on two other pages. In each, click the line where reality stopped matching the paper, then click the ticket note that would survive a review.",
        lead: "Two closed tickets from the binder review. The analysts' names are covered.",
        howTo: ["Read the page against the ticket, line by line.", "Click the line where they stopped matching.", "Then click the note that belongs in the ticket."],
        steps: [
          {
            id: "s1",
            ask: "PB-31, Lost handheld scanner. Click the line where the page stopped matching.",
            source: "GFD-INC-3244 · PB-31 against the ticket",
            columns: ["Step", "The page says", "What the analyst found"],
            rows: [
              ["1", "Get the driver's loss report", "Report on file, 06:10"],
              ["2", "Check the last check-in in device management", "06:52 today, North depot Wi-Fi, a different user signed in"],
              ["3", "Remote wipe the handheld", "Not run yet"],
              ["4", "Issue a replacement", "Not run yet"],
            ],
            answer: 1,
            why: "A lost handheld doesn't sign in. Step 3 would erase the one thing that can say who has it. Steps 3 and 4 haven't happened, so the break is where the first reading disagrees with what the page assumes.",
            learned: "PB-31 assumes nobody is using the handheld. The check-in says somebody is.",
          },
          {
            id: "s2",
            ask: "Which note goes in the ticket?",
            source: "GFD-INC-3244 · draft notes",
            columns: ["Draft", "Ticket note"],
            rows: [
              ["A", "Wipe not run. It didn't feel right, so I passed it up to the day shift and moved on to the next ticket in the queue."],
              ["B", "Wipe run as the page says. Worth mentioning that the handheld had checked in that morning."],
              ["C", "Stopped before Step 3. 06:52 check-in on North Wi-Fi under a new user, so not lost. Wipe not run. Paged IR 07:01."],
            ],
            answer: 2,
            why: "C names the step, the evidence, what wasn't done and who was told, while it was happening. A gives a feeling that nobody else can check. B records the evidence after destroying the thing it pointed at.",
            learned: "A note says which step, what evidence, what was and wasn't done, and who was told.",
          },
          {
            id: "s3",
            ask: "PB-15, Reported phishing mail. Click the line where the page stopped matching.",
            source: "GFD-INC-3259 · PB-15 against the ticket",
            columns: ["Step", "The page says", "What the analyst found"],
            rows: [
              ["1", "Find the mail in the reporter's mailbox", "Message trace on the sender, all Greenhithe mail, 7 days: no copy. It reached a personal address."],
              ["2", "Pull headers and links from the original", "Done from the copy the reporter forwarded"],
              ["3", "Search all mailboxes for the sender", "Not run yet"],
              ["4", "Purge every copy", "Not run yet"],
              ["5", "Reply to the reporter", "Not run yet"],
            ],
            answer: 0,
            why: "The page assumes a mail in a Greenhithe mailbox, and this one never arrived. Nobody needs waking: this is a small step-off, and the rest of the page has nothing to act on.",
            learned: "PB-15 assumes the mail reached Greenhithe. It never did.",
          },
          {
            id: "s4",
            ask: "Steps 3 and 4 won't run. Which note goes in the ticket?",
            source: "GFD-INC-3259 · draft notes",
            columns: ["Draft", "Ticket note"],
            rows: [
              ["A", "Steps 3 and 4 skipped as the reporter was sure this was a one-off, and the queue was long tonight, so the time went on other tickets."],
              ["B", "Steps 3 and 4 skipped. Message trace on the sender, all Greenhithe mail, 7 days: no copy. It reached a personal address. Reporter told 14:20."],
              ["C", "Closed per page."],
            ],
            answer: 1,
            why: "A skipped step isn't the fault. A skipped step without a reason someone can check is. B's reason can be re-run by anyone. A's reason is about the queue, and C claims the page was followed when it wasn't.",
            learned: "A skipped step needs a reason someone else can check.",
          },
        ],
      },
      {
        kind: "codebreak",
        title: "Four Words for the Ticket",
        prompt: "Sanaa won't accept a ticket that says it looked bigger. These four words say what you mean. Read each clue, guess, and use the letter feedback.",
        rounds: [
          { id: "scope", clue: "5 letters. The line at the top of a page that says which situation it was written for.", answer: "SCOPE", why: "The scope condition. The step that tests it is the scope gate, and it's the only step on a page that can tell you the page is wrong." },
          { id: "pivot", clue: "5 letters. Moving a search from the name on the ticket to the event's own properties.", answer: "PIVOT", why: "Search by name and you learn how bad it is for that name. Pivot and you learn how big it is." },
          { id: "asn", clue: "3 letters. Autonomous System Number, as analysts write it: the number naming the network an address belongs to, as in AS64500.", answer: "ASN", why: "Sign-in records carry it in AutonomousSystemNumber. One ASN can be a broadband firm with millions of customers or a tiny hosting provider, so read it alongside the other fields." },
          { id: "floor", clue: "5 letters. Sanaa's rule: a playbook is a ____, not a ceiling.", answer: "FLOOR", why: "The page is the least you do, never the limit of what you may notice. The steps you run are the floor, and your judgement stands on them." },
        ],
        lesson: "Scope is what a page assumes, a pivot is how you test it, and an ASN is one of the properties you test it with. Saying exactly what you checked is what lets the next person trust your decision.",
      },
    ],
    // ── Task: validate and collect ──
    "pbk-la1": [
      {
        kind: "anatomy",
        title: "Read a Sign-In Record Field by Field",
        prompt: "22:51. While you capture GFD-DISP-07, its user tries to open the depot portal, and the identity log records the attempt. Before you lean on any record like this, learn what each field really says. Scan every field.",
        source: "Entra ID · SignInLogs · j.hartley · 22:51",
        fields: [
          { key: "UserPrincipalName", value: "j.hartley@greenhithefoods.example", label: "Who", note: "The sign-in name, shortened to UPN. It tells you which account, not which person." },
          { key: "AppDisplayName", value: "Greenhithe Depot Portal", label: "To what" },
          { key: "IPAddress", value: "198.51.100.24", label: "From", note: "South depot's own internet exit, shared by everyone on that site." },
          { key: "ResultType", value: "53000", label: "Outcome", note: "Read this first. 0 is Entra's code for a sign-in that completed. Any other number is why it didn't. 53000 means Conditional Access (CA) required a compliant device and this one isn't." },
          { key: "AuthenticationDetails", value: "[{\"authenticationMethod\":\"Password\",\"succeeded\":true},{\"authenticationMethod\":\"Mobile app notification\",\"succeeded\":true}]", label: "Factors", note: "One entry per factor, each with its own result. Both passed here, and still no access was granted. These entries show how far it got, and ResultType shows how it ended, so read them together." },
          { key: "ConditionalAccessStatus", value: "failure", label: "Policy", note: "success: policies applied and were met. failure: a policy blocked it, as here. notApplied: no policy was in scope for this sign-in. Policies are scoped by application, so the value describes this sign-in to this app." },
          { key: "AuthenticationRequirement", value: "multiFactorAuthentication", label: "Needed", note: "What this sign-in demanded. singleFactorAuthentication means a password alone was enough here. multiFactorAuthentication means a second factor counted." },
          { key: "DeviceDetail.isCompliant", value: "false", label: "Device", note: "The EDR raised this PC's risk, device management marked it non-compliant, and that's what the policy checked." },
          { key: "RiskLevelDuringSignIn", value: "low", label: "Opinion", note: "Entra's real-time view of how unusual this looked for this user. An opinion about how the sign-in looked, set at that moment. Here it's low, on a sign-in that was stopped." },
          { key: "CorrelationId", value: "0e7b1c42-6d19-4f3a-9a70-5c2e81d4b6f3", label: "Grouping", note: "Quote it to support to find this exact attempt." },
        ],
        summary: "Ask the record two separate things. Did it happen? That's ResultType, with the factor entries behind it. How unusual did it look? That's risk, and it's only an opinion. The Conditional Access fields describe what was asked of this sign-in to this application. j.hartley reached nothing here: the password was right, the prompt was approved, and the policy stopped it at the door because the PC had turned non-compliant. Note it in the capture, and change nothing.",
      },
    ],
    // ── Task: why collect before you contain ──
    "pbk-q1": [
      {
        kind: "match",
        title: "What the Fix Leaves Behind",
        prompt: "The South depot manager wants GFD-DISP-07 rebuilt right now, before anyone captures anything. Each fix on the left closes one thing and misses another. Match each fix to what it would leave running, so you can say why capture comes first.",
        pairs: [
          { id: "rebuild", left: "Rebuild the PC", right: "A scheduled task the malware made on a file server", why: "A rebuild cleans one disk. What was planted elsewhere lives on, and only the capture would have pointed you at it." },
          { id: "kill", left: "Kill the process", right: "The Run key that starts it again at the next logon", why: "Ending a process takes what was in its memory with it. A Run key is a registry entry that starts a program at logon, so it comes straight back." },
          { id: "block", left: "Block the one domain", right: "A second domain in the implant's configuration", why: "The operator sees the first channel die and the implant falls back to the next. You've warned them, and you've stopped watching the traffic that would have shown you the second." },
          { id: "pass", left: "Change the local admin password", right: "A remote-access tool that never used that password", why: "Installed access doesn't log in with the thing you changed. A fix only removes what it touches, so you need to know what's there first." },
        ],
      },
    ],
    // ── Task: what each step produces ──
    "pbk-m1": [
      {
        kind: "sort",
        title: "Done, or Only Ticked?",
        prompt: "Sanaa reads tickets, not tick boxes. A step is done when it has left something another person can check. Sort these lines from old PB-22 tickets.",
        buckets: [
          { id: "done", label: "Done" },
          { id: "ticked", label: "Only ticked" },
        ],
        items: [
          { id: "a", text: "Step 1: Confirmed.", bucket: "ticked", why: "Confirmed from what? Step 1 should leave a determination with its basis, so nobody has to ask." },
          { id: "b", text: "Step 1: File on disk, SHA256 recorded, not a repeat of GFD-INC-3271.", bucket: "done", why: "A decision that the detection is real, with what it rests on." },
          { id: "c", text: "Step 2: Looked at the PC, nothing obvious.", bucket: "ticked", why: "Looked at what? Nothing was kept, so nothing can be checked." },
          { id: "d", text: "Step 2: Package taken 23:02 before any change: process tree, connections, persistence, file copy.", bucket: "done", why: "A set of evidence, and the time shows it came before anything was changed." },
          { id: "e", text: "Step 3: Searched GFD-PICK-04. Only GFD-PICK-04 came back.", bucket: "ticked", why: "It looks like a search, but a search on the host name can only return the host name. The step's question was never asked." },
          { id: "f", text: "Step 3: Fleet search on SHA256 and domain, 24 hours: GFD-PICK-04 only. One-workstation line holds.", bucket: "done", why: "The search, its window, the result, and an explicit answer to the page's condition." },
          { id: "g", text: "Step 4: Isolated 23:40, file removed, rebuild job logged.", bucket: "done", why: "The first deliberate changes to the host, each one traceable." },
          { id: "h", text: "Step 5: Closed.", bucket: "ticked", why: "Nobody reading this in six months can tell what happened without asking someone." },
          { id: "i", text: "Step 5: Back with Stock at 09:15, line manager told, summary says what ran, how it arrived and what was done.", bucket: "done", why: "The person has the PC back, and a stranger can follow the story." },
        ],
      },
    ],
    // ── Task: the scope query ──
    "pbk-la2": [
      {
        kind: "worksheet",
        title: "Ask It the Other Way Round",
        prompt: "Back on tonight's ticket, GFD-INC-3318. Step 3 says measure it. Run both searches over this table and answer from the rows.",
        primer: {
          title: "Two searches, two questions",
          points: [
            "A search on the name in the ticket asks **how bad is it here?** It can only return that name, so it can only agree with you.",
            "A search on the event's own properties asks **how big is it?** That one can come back with a different answer.",
            "Detections judge one event at a time. Something that looks ordinary in one place raises nothing there, however loud it is somewhere else.",
          ],
          example: {
            label: "The method, on a yoghurt recall",
            lines: [
              "A shop reports a blown pot. Search complaints by shop name: one row, that shop.",
              "Search dispatch records by batch code L2291: eleven shops received it.",
              "Ten of them haven't complained. That doesn't make them fine. Nobody there has opened a pot yet.",
            ],
          },
        },
        caption: "Advanced hunting · files and connections by device · last 24 hours",
        columns: ["DeviceName", "Department", "Site", "SHA256 (first 8)", "RemoteUrl", "Alerts in queue"],
        rows: [
          ["GFD-DISP-07", "Dispatch", "South depot", "3fa91c0e", "sync.routecdn.example", "1"],
          ["GFD-PAY-02", "Payroll", "Head office", "3fa91c0e", "sync.routecdn.example", "0"],
          ["GFD-STOCK-09", "Stock Control", "South depot", "77b04d12", "updates.rtplanner.example", "0"],
          ["GFD-HR-05", "HR", "Head office", "3fa91c0e", "sync.routecdn.example", "0"],
          ["GFD-FLEET-11", "Fleet Workshop", "North depot", "3fa91c0e", "sync.routecdn.example", "0"],
          ["GFD-TILL-01", "Staff Shop", "Head office", "c8e2a640", "updates.labeldesk.example", "0"],
          ["GFD-COLD-03", "Cold Store Office", "North depot", "3fa91c0e", "sync.routecdn.example", "0"],
        ],
        questions: [
          { id: "name", q: "Search on DeviceName == \"GFD-DISP-07\". How many devices can that ever return?", hint: "What did you ask for?", answer: ["1", "one"], why: "One, however bad things are. The query can only confirm what the ticket already said." },
          { id: "hash", q: "Now search on the SHA256 starting 3fa91c0e. How many devices?", hint: "Count the matching rows.", answer: ["5", "five"], why: "Five, against one in the ticket. Same question to the same data, asked the other way round." },
          { id: "queue", q: "How many alerts sit in the queue for those devices?", hint: "Add up the last column on the matching rows.", answer: ["1", "one"], why: "One. On GFD-DISP-07 somebody started the file by hand and tripped a behaviour rule. On the other four it ran under the software deployment agent and looked routine. Each detection judged its own device, so a queue of one tells you how many alerts fired and nothing more." },
          { id: "dept", q: "How many different departments do the matching devices cover?", hint: "Read the Department column.", answer: ["5", "five"], why: "No shared team and no shared manager, so nothing about the people connects them. All five pulled the file from one deployment share. The common factor isn't any PC. It's whatever delivered the file." },
        ],
      },
      {
        kind: "intercept",
        title: "Count It, or Rule It Out?",
        prompt: "Sanaa asks you to check the widest search before you quote a number. Not every hit belongs in the count, and a wrong count misleads whoever reads your note. Count the devices that share a real fingerprint with GFD-DISP-07. Rule out the coincidences.",
        primer: {
          title: "One match is a lead",
          points: [
            "A pivot returns matches, not proof. Each one needs a reason to stay in the count.",
            "**One shared value is weak.** A whole town shares a country, a whole site shares an exit address through **NAT** (Network Address Translation), and a patched fleet shares a browser build.",
            "**Several exact values together are strong.** Rarer ones weigh more: a file hash, an unusual URL path, a small network.",
            "A **user agent** is the text a browser or tool sends to say what it is.",
          ],
          example: {
            label: "The method, on two complaints",
            lines: [
              "Two complaints from one town: a lead, no more.",
              "Two complaints with one batch code, one lorry and one delivery date: one cause.",
            ],
          },
        },
        protect: "the scope count",
        blockLabel: "Count it",
        passLabel: "Rule it out",
        seconds: 12,
        items: [
          { id: "i1", text: "GFD-HR-05: same SHA256, same RemoteUrl, same deploy share path", sub: "HR, head office, 22:33", bad: true, why: "Three exact values, one of them a file fingerprint. It didn't raise an alert, and it still counts." },
          { id: "i2", text: "GFD-TILL-01: same country as the server behind the domain", sub: "No shared hash, no shared URL", bad: false, why: "Country alone is the weakest match there is. Millions of things share it." },
          { id: "i3", text: "GFD-FLEET-11: same domain, same URL path, same user agent", sub: "Fleet Workshop, North depot, 22:36", bad: true, why: "A rare path and a matching tool string from a PC with no reason to know either." },
          { id: "i4", text: "86 PCs: same public IP as GFD-DISP-07", sub: "South depot's own internet exit", bad: false, why: "Everyone on the site leaves through that one address. It's NAT, not a fingerprint." },
          { id: "i5", text: "190 PCs: same browser user agent", sub: "The browser build IT pushed last Tuesday", bad: false, why: "A common string on a patched fleet tells you about the patch." },
          { id: "i6", text: "GFD-PAY-02: same SHA256, same deploy share path", sub: "Payroll, head office, 22:31", bad: true, why: "The file's own fingerprint, from the same place. Payroll and Dispatch share nothing else." },
          { id: "i7", text: "GFD-SOC-VM2: same SHA256", sub: "Your own analysis VM, file copied there tonight", bad: false, why: "That's you. Rule out your own traces, or the count includes your investigation." },
          { id: "i8", text: "GFD-STOCK-09: same file name, rtplan_update.exe", sub: "Different SHA256, signed by the route-planner vendor", bad: false, why: "A name is a label anyone can use. The hash and the signer say it's a different file." },
          { id: "i9", text: "GFD-COLD-03: same SHA256, same RemoteUrl", sub: "Cold Store Office, North depot, 22:37", bad: true, why: "Same file, same call-out, inside the same seven minutes as the others." },
          { id: "i10", text: "GFD-SALES-12: same ASN as the domain's server", sub: "A cloud provider half the internet uses", bad: false, why: "A huge shared network proves almost nothing. On a small hosting network, the same match would weigh far more." },
        ],
        lesson: "Count on stacked exact values, weigh the rare ones most, and rule out anything explained by shared infrastructure or by your own work. With GFD-DISP-07, that's five. Say how you got there, because the count is only as good as the reasons behind it.",
      },
      {
        kind: "sort",
        title: "What Came Before the Success?",
        prompt: "Sanaa's old notes from the carrier portal, where hauliers sign in to book loading bays. How a password was obtained shows in what came before the success. Sort each sign-in history.",
        primer: {
          title: "What comes before the success",
          points: [
            "**Brute force** tries many passwords on one account. A **spray** tries one password on many accounts.",
            "Trying produces failures, and failures get logged.",
            "So don't stop at the success. Read what the same source did before it.",
          ],
          example: {
            label: "The method, on a padlock",
            lines: [
              "Forty scratches round the keyhole: someone was trying.",
              "No scratches, and it opened first time: someone had a key. Whose key is the next question.",
            ],
          },
        },
        buckets: [
          { id: "guess", label: "Guessing" },
          { id: "held", label: "Password known" },
          { id: "owner", label: "The owner's typo" },
        ],
        items: [
          { id: "a", text: "412 failures from one address across 300 accounts, then one success", bucket: "guess", why: "One password against many accounts: a spray, and the log shows every miss." },
          { id: "b", text: "900 failures on one account in ten minutes, then a success", bucket: "guess", why: "Brute force. Loud, and the failures are the evidence." },
          { id: "c", text: "No failures from this address in 30 days, then a correct password first time, from a country this haulier has never used", bucket: "held", why: "No attempts means no guessing, so whoever typed it already knew it. The next job is finding where the password leaked." },
          { id: "d", text: "Two failures, then a success, from the haulier's usual office at the start of a shift", bucket: "owner", why: "Few failures, a familiar place, a normal time. Failures alone don't make an attack." },
          { id: "e", text: "Thirty failures an hour across thirty accounts for two days, then one success", bucket: "guess", why: "A slow spray, kept under lockout limits. It's still a run of failures." },
          { id: "f", text: "First-try success from a new address, on an account seen in a phishing kit's log last week", bucket: "held", why: "The password was taken somewhere else, and no attempt shows here." },
          { id: "g", text: "One failure just after a password change, then a success, on the user's own laptop", bucket: "owner", why: "An old password typed from habit. Check it once and move on." },
        ],
      },
    ],
    // ── Boss: the decision ──
    "pbk-ac1": [
      {
        kind: "defuse",
        title: "Which Branch Applies?",
        prompt: "Sanaa's board for nights: four situations, and the last is yours. Each shows what the page says and what's in front of you. Cut the one branch that fits before the clock runs out. A wrong cut costs ten seconds.",
        primer: {
          title: "Three ways a page can go",
          points: [
            "**Carry on.** The scope condition holds, so finish the page. Most tickets end here, and that's a full result.",
            "**Step off one line.** The line no longer works but its purpose stands. Do what it was for, note why, and tell the page's owner.",
            "**Stop.** This isn't the situation the page was written for. Don't start the step that changes things, and page whoever is on call, at any hour.",
            "An exit line is part of the page, so taking it is following the page. A page with no exit line doesn't trap you: you can still stop, and the record matters even more.",
            "A count is only as wide as the search behind it.",
          ],
          example: {
            label: "The method, in the cold store",
            lines: [
              "CS-3 covers an open door. Probe warm, door open: shut it and carry on.",
              "CS-3 names a probe replaced last month: read the new one, note it, tell the owner.",
              "Probe warm, door shut, compressor alarm sounding: that isn't a door. Stop and call refrigeration.",
            ],
          },
        },
        device: "The branch board",
        seconds: 90,
        rounds: [
          {
            id: "rename",
            state: "PB-22 covers one workstation. The fleet search returns two names, GFD-STOCK-04 and GFD-PICK-04, with one DeviceId. A rename ticket went through on Tuesday.",
            wires: [
              { id: "a", label: "Stop and page Sanaa: there are two hosts" },
              { id: "b", label: "Carry on to Step 4" },
              { id: "c", label: "Treat them as two and rebuild both" },
            ],
            cut: "b",
            hint: "Count machines, not names.",
            why: "One DeviceId is one machine under an old name and a new one, so the scope line holds. Stopping here would spend someone's night on a rename. Most gates open, and that's the point of checking.",
          },
          {
            id: "image",
            state: "PB-22 Step 4 says rebuild from image GFD-W11-A. That image was withdrawn last month, and the build team now issues GFD-W11-B.",
            wires: [
              { id: "a", label: "Hold the case until the page is reissued" },
              { id: "b", label: "Use GFD-W11-B and say nothing" },
              { id: "c", label: "Use GFD-W11-B, note why, tell the owner" },
            ],
            cut: "c",
            hint: "Does the step's purpose still stand?",
            why: "The purpose stands and the line doesn't. A quiet swap leaves a ticket that disagrees with its page and no reason why. Holding the case keeps a user out of work over a typo.",
          },
          {
            id: "noexit",
            state: "PB-17 says block the sender's domain at the mail gateway. The sender is the dairy behind 300 orders a day, and one of its staff was phished. PB-17 has no exit line.",
            wires: [
              { id: "a", label: "Hold the block, page Sanaa, record why" },
              { id: "b", label: "Block the domain, as written" },
              { id: "c", label: "Skip the block and close the ticket" },
            ],
            cut: "a",
            hint: "Who did the author picture as the sender?",
            why: "The page pictured a stranger's domain. Blocking this one stops tomorrow's orders, and skipping it quietly leaves the real risk open. No exit line means this is a true deviation, so the record is what makes it stand up.",
          },
          {
            id: "tonight",
            state: "Tonight. PB-22 covers one workstation. Five devices, five departments, one alert, one deployment share. Step 4 is clear, and Sanaa is asleep and on call.",
            wires: [
              { id: "a", label: "Rebuild all five, then close the ticket" },
              { id: "b", label: "Stop at Step 3, page Sanaa, keep it open" },
              { id: "c", label: "Rebuild this PC, flag the rest for morning" },
            ],
            cut: "b",
            hint: "Whatever delivered the file: does any step on this page touch it?",
            why: "The page's condition has failed, and its last line says stop. Rebuilding one leaves four and closes the ticket. Rebuilding five looks complete, but five is only what a 24-hour search returned, and the share that delivered the file is untouched. Morning means hours more of whatever it's doing.",
          },
        ],
        lesson: "The decision comes from the page's own condition, set beside what you found. When the common factor isn't the thing the page acts on, finishing the page changes nothing that matters, however clear the next step looks.",
      },
    ],
    // ── Task: what makes a step-off defensible ──
    "pbk-q2": [
      {
        kind: "queue",
        title: "Sign It Off, or Send It Back?",
        prompt: "Sanaa's Friday job: every ticket where a step didn't run gets read before it can stay closed. Open each one, read the record, and decide whether it stands up on its own.",
        primer: {
          title: "Reading a ticket as a stranger",
          points: [
            "Read each ticket as someone who wasn't there, six months from now.",
            "Ask: could that person tell **what** was left undone, **why**, and **who knew**?",
            "Check the times as well as the words.",
          ],
          example: {
            label: "The method, on a forklift check",
            lines: [
              "Skipped horn test.",
              "Horn test skipped: fuse out, truck tagged off, shift lead told 06:10.",
              "The first leaves a question. The second leaves nothing to ask.",
            ],
          },
        },
        console: "Ticket review · Steps not run",
        actions: [
          { id: "sign", label: "Sign off the record", tone: "close" },
          { id: "back", label: "Send back to the analyst", tone: "escalate" },
        ],
        alerts: [
          {
            id: "a1", time: "Fri 09:02", severity: "Medium", rule: "PB-22 Malware on one workstation", entity: "GFD-INC-3275",
            fields: [{ k: "Step not run", v: "Step 3" }, { k: "Ticket note", v: "Step 3 skipped." }, { k: "Note written", v: "During the shift" }],
            context: "The ticket was closed after a rebuild. Nothing else went wrong.",
            answer: "back",
            why: "The one step that could have shown the page was wrong is gone, with no reason. A reader can't tell a decision from abandoned work.",
          },
          {
            id: "a2", time: "Fri 09:06", severity: "Low", rule: "PB-22 Malware on one workstation", entity: "GFD-INC-3301",
            fields: [{ k: "Step not run", v: "Step 2 as written" }, { k: "Ticket note", v: "CollectKit gone with GFD-IT01, used Collect investigation package." }, { k: "Note written", v: "14:12, before Step 3" }],
            context: "Page owner told the same afternoon.",
            answer: "sign",
            why: "The step, the reason, what was done instead, written while it happened. Nothing is left to ask.",
          },
          {
            id: "a3", time: "Fri 09:11", severity: "High", rule: "PB-40 Ransom note on a share", entity: "GFD-INC-3286",
            fields: [{ k: "Step not run", v: "Steps 3 to 5" }, { k: "Ticket note", v: "Stopped. Right call, Sanaa agreed on the phone." }, { k: "Note written", v: "During the shift" }],
            context: "The incident was handled well. Sanaa remembers the call.",
            answer: "back",
            why: "Stopped, on what evidence? A phone call leaves nothing a stranger can read. When someone else picks this up, all they have is the ticket.",
          },
          {
            id: "a4", time: "Fri 09:15", severity: "High", rule: "PB-22 Malware on one workstation", entity: "GFD-INC-3307",
            fields: [{ k: "Step delayed", v: "Step 4, by 41 minutes" }, { k: "Ticket note", v: "GFD-CSTORE-02 carries the freezer alarms. Domain blocked 03:12, paged Sanaa 03:14, isolated 03:55 once probes were being read by hand." }, { k: "Note written", v: "03:14, updated 03:55" }],
            context: "Depot manager copied on the ticket.",
            answer: "sign",
            why: "Which step, why, what was done meanwhile, who was told, with the times to prove it.",
          },
          {
            id: "a5", time: "Fri 09:20", severity: "Medium", rule: "PB-15 Reported phishing mail", entity: "GFD-INC-3263",
            fields: [{ k: "Step not run", v: "Step 4" }, { k: "Ticket note", v: "Purge held: legal hold on that mailbox, confirmed with Legal." }, { k: "Note written", v: "Nine days after closure, when the audit asked" }],
            context: "The wording is good. The ticket sat closed for nine days with nothing in it.",
            answer: "back",
            why: "A good sentence, written after the fact. For nine days nobody could have known a purge hadn't run. Record it at the time, and mark a late note as late.",
          },
        ],
      },
    ],
    // ── Reading 3: deviating properly ──
    "pbk-r3": [
      {
        kind: "sequence",
        title: "Build the Page to Sanaa",
        prompt: "23:31. You're paging Sanaa. These five lines are all true. Tap them in the order someone just woken needs to hear them.",
        primer: {
          title: "What the person you wake needs",
          points: [
            "They have one decision to make: what happens in the next few minutes. Give them what that needs and nothing else.",
            "Lead with the finding, then what backs it, then why it's theirs and not yours.",
            "Then the levers: what you've pulled, and what you haven't. They can't decide without that.",
            "Finish with where your search stopped.",
            "Stick to what you saw. How it got in is the incident they're about to open.",
          ],
          example: {
            label: "The shape, from the cold store",
            lines: [
              "Bay 4 and the compressor alarm fired together at 01:10.",
              "Probe log attached, door shut, compressor room at 31 C.",
              "CS-3 covers an open door, so this one is yours.",
              "Nothing moved, nothing switched off.",
              "I've only read bay 4 so far.",
            ],
          },
        },
        items: [
          { id: "done", text: "Steps 1 to 3 done, evidence held. Nothing isolated, nothing rebuilt, nobody told.", note: "The levers. Sanaa's first decision depends on knowing none of them has been pulled." },
          { id: "limits", text: "I searched 24 hours on this hash and domain, so five is the least it could be.", note: "A bounded finding is useful. A number with no bounds gets planned around as if it were the truth." },
          { id: "have", text: "Five Greenhithe devices ran the same unsigned file between 22:31 and 22:38.", note: "The finding, in one line, with no theory attached." },
          { id: "why", text: "PB-22 covers one workstation, so its Step 4 wouldn't contain this.", note: "Why it's being raised and not handled. It's the page's own condition, not a hunch." },
          { id: "evidence", text: "One SHA256 and one domain on all five, across five departments, and one alert between them.", note: "What backs the finding, specific enough to re-run." },
        ],
        order: ["have", "evidence", "why", "done", "limits"],
        doneNote: "Finding, evidence, why it's escalated, what's been done and not done, and the limits of what you know. Notice what isn't there: no theory about how the file got on to the share. That's the incident Sanaa is about to open. GFD-INC-3318 stays open, with its unticked steps showing, and that's an accurate ticket.",
      },
      {
        kind: "match",
        title: "What the Binder Gets From Your Ticket",
        prompt: "A week later Sanaa has the ticket open beside PB-22. Your note decides what changes. Match each line from a ticket to what it becomes.",
        pairs: [
          { id: "query", left: "Fleet search on SHA256 is what surfaced the four quiet devices", right: "A written query, added to Step 3 as a required sub-step", why: "The next analyst runs it by default, and doesn't have to invent it at 03:00." },
          { id: "share", left: "No log of who can write to the deployment share", right: "A coverage review, separate from this incident", why: "That finding leaves the incident and becomes a permanent fix, not a one-off clean-up." },
          { id: "tool", left: "CollectKit gone with GFD-IT01", right: "Step 2 reissued with the current tool", why: "A stale line reported the same day is a stale line nobody trips on twice." },
          { id: "cold", left: "GFD-CSTORE-02 carries the freezer alarms", right: "A flag on the asset record, and a check before Step 4", why: "Now the page knows about the PC's second job." },
          { id: "none", left: "Escalated.", right: "Nothing changes, and the next analyst meets the same gap", why: "A note with nothing in it teaches the binder nothing. Your ticket is how the page gets better." },
        ],
      },
    ],
  },
};
