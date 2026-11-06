import type { BriefingLab, RoomExperience } from "./types";

// "Operation Reply All" for the "exchange-online-security" room.
// Script: docs/campaign/56-exchange-online-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Thistledown Seed Co-op (fictional), not the graded tasks' corp.com records.
// Signature mechanic: portal in a new Exchange-style skin, a message trace with a details
// flyout, then the audit search, ending in the one inbox rule behind a hijacked thread.
// Game mix: defuse + intercept + pathway + portal + rush.
// Lab data differs from the graded tasks: no lookalike domain (q2, la1, flag1), no SCL -1
// (r1 checkpoint), no spf=pass dkim=pass dmarc=fail header (q1), no forwarded newsletter
// (r2 checkpoint), and no mailbox-level forwarding (q3): every console record here is an
// inbox rule, and the word Set-Mailbox never appears. No 185.234.91.7.

type Portal = Extract<BriefingLab, { kind: "portal" }>;

const TRACE_LAB: Portal = {
  kind: "portal",
  skin: "exchange",
  title: "Work the Thread",
  prompt: "Tuesday, 09:10. A seed supplier rang Thistledown's treasurer: their invoice is still unpaid, yet the co-op says it paid. The payment went to a new bank account, requested in a reply on the real thread. Sefa Mensah opens the admin center and pulls up a chair. Find out how that reply got there.",
  product: "Mail admin center",
  resource: "Thistledown Seed Co-op",
  tenant: "thistledown.example",
  home: "home",
  menu: [
    { items: [{ id: "home", label: "Home" }] },
    { group: "Recipients", items: [{ id: "mailboxes", label: "Mailboxes" }] },
    { group: "Mail flow", items: [{ id: "trace", label: "Message trace" }, { id: "rules", label: "Rules" }] },
    { group: "Compliance", items: [{ id: "audit", label: "Audit" }] },
  ],
  pages: {
    home: { heading: "Home", tiles: [{ label: "Mailboxes", value: "212" }, { label: "Messages today", value: "3,418" }, { label: "In quarantine", value: "37" }], note: "Everything you need for this job is in the menu on the left." },
    mailboxes: {
      heading: "Manage mailboxes",
      table: {
        columns: ["Display name", "Email address", "Recipient type", "Archive status"],
        rows: [
          { id: "m-ob", cells: ["Ona Bright", "o.bright@thistledown.example", "UserMailbox", "Active"], record: "m-ob" },
          { id: "m-ps", cells: ["Pavel Sandoval", "p.sandoval@thistledown.example", "UserMailbox", "Active"], record: "m-ps" },
          { id: "m-ar", cells: ["Accounts", "accounts@thistledown.example", "SharedMailbox", "None"], record: "m-ar" },
        ],
      },
    },
    trace: {
      heading: "Message trace",
      filters: ["Recipient: o.bright@thistledown.example", "Time range: Last 7 days", "Delivery status: All"],
      table: {
        columns: ["Date (UTC)", "Sender", "Subject", "Status"],
        rows: [
          { id: "t-1", cells: ["Mon 16:42", "invoices@harrowfield-seed.example", "Invoice 40711, spring order", "Delivered"], record: "t-1" },
          { id: "t-2", cells: ["Mon 17:05", "p.sandoval@thistledown.example", "RE: Invoice 40711, spring order", "Delivered"], record: "t-2", tone: "high" },
          { id: "t-3", cells: ["Mon 17:31", "mailer@prize-draw-now.example", "You have won a tractor", "Quarantined"], record: "t-3", tone: "low" },
        ],
      },
    },
    rules: {
      heading: "Rules",
      note: "Rules here are tenant-wide transport rules, set by admins. Nothing has changed this month. A rule a user makes in their own mailbox doesn't live on this page.",
    },
    audit: {
      heading: "Audit",
      filters: ["Users: p.sandoval@thistledown.example", "Date range: Last 7 days", "Workload: Exchange"],
      table: {
        columns: ["Date (UTC)", "IP address", "Activity", "Item"],
        rows: [
          { id: "a-new", cells: ["Mon 02:51", "203.0.113.141", "New-InboxRule", ".."], record: "a-new", tone: "high" },
          { id: "a-old", cells: ["Mar 03 10:12", "198.51.100.40", "New-InboxRule", "Seed catalogues"], record: "a-old" },
          { id: "a-send", cells: ["Mon 17:04", "203.0.113.141", "Send", "RE: Invoice 40711"], record: "a-send" },
          { id: "a-log", cells: ["Mon 08:30", "198.51.100.40", "MailboxLogin", "Outlook"], record: "a-log" },
        ],
      },
    },
  },
  records: {
    "t-1": { id: "t-1", title: "Message trace details", facts: [["Subject", "Invoice 40711, spring order"], ["Sender", "invoices@harrowfield-seed.example"], ["Status", "Delivered"]], timeline: [{ time: "16:42", text: "Receive" }, { time: "16:42", text: "Deliver: Inbox" }] },
    "t-2": {
      id: "t-2",
      title: "Message trace details",
      facts: [["Subject", "RE: Invoice 40711, spring order"], ["Sender", "p.sandoval@thistledown.example"], ["Direction", "Internal"], ["Connecting from", "Outlook on the web, 203.0.113.141"], ["Body says", "Harrowfield has moved banks. New details attached, please use them for this payment."]],
      timeline: [{ time: "17:05", text: "Submit" }, { time: "17:05", text: "Send" }, { time: "17:05", text: "Deliver: Inbox" }],
      actions: [{ id: "headers", label: "View headers" }, { id: "release", label: "Report as junk" }],
      panes: { headers: [["Authentication", "Internal, signed by the tenant"], ["SCL", "1"], ["Filtering", "Clean: no malware, no phish verdict"], ["Meaning", "The real mailbox sent this"]] },
    },
    "t-3": { id: "t-3", title: "Message trace details", facts: [["Subject", "You have won a tractor"], ["Status", "Quarantined"], ["Reason", "High confidence spam"]], timeline: [{ time: "17:31", text: "Receive" }, { time: "17:31", text: "Quarantine" }] },
    "a-new": { id: "a-new", title: "New-InboxRule", facts: [["Mailbox", "p.sandoval@thistledown.example"], ["Client IP", "203.0.113.141"], ["Client", "Outlook on the web"], ["Name", ".."], ["SubjectOrBodyContainsWords", "invoice;remittance;bank"], ["MoveToFolder", "RSS Feeds"], ["MarkAsRead", "True"], ["StopProcessingRules", "True"]] },
    "a-old": { id: "a-old", title: "New-InboxRule", facts: [["Mailbox", "p.sandoval@thistledown.example"], ["Name", "Seed catalogues"], ["From", "catalogues@harrowfield-seed.example"], ["MoveToFolder", "Catalogues"]] },
    "a-send": { id: "a-send", title: "Send", facts: [["Mailbox", "p.sandoval@thistledown.example"], ["Client IP", "203.0.113.141"], ["Subject", "RE: Invoice 40711, spring order"]] },
    "a-log": { id: "a-log", title: "MailboxLogin", facts: [["Mailbox", "p.sandoval@thistledown.example"], ["Client IP", "198.51.100.40"], ["Note", "The co-op's office address, at the start of the working day"]] },
    "m-ps": { id: "m-ps", title: "Pavel Sandoval", facts: [["Email address", "p.sandoval@thistledown.example"], ["Department", "Purchasing"], ["Inbox rules", "2"]], actions: [{ id: "signout", label: "Sign out all sessions" }, { id: "wipe", label: "Delete mailbox" }] },
    "m-ob": { id: "m-ob", title: "Ona Bright", facts: [["Email address", "o.bright@thistledown.example"], ["Department", "Treasury"], ["Inbox rules", "0"]], actions: [{ id: "signoutob", label: "Sign out all sessions" }] },
    "m-ar": { id: "m-ar", title: "Accounts", facts: [["Email address", "accounts@thistledown.example"], ["Type", "Shared mailbox"]] },
  },
  steps: [
    { id: "trace", ask: "Start with the tool that tracks a single message.", hint: "Mail flow, in the menu on the left.", target: "menu:trace", why: "Message trace answers the delivery questions: who sent it, who got it, and what happened on the way. The filter is already on the treasurer." },
    { id: "row", ask: "Open the reply that asked for the new bank details.", hint: "It's on the invoice thread, and it isn't the first message.", target: "row:t-2", why: "This isn't from the supplier. The sender is Pavel Sandoval in Purchasing, a colleague on the same thread, and the reply went internally." },
    { id: "headers", ask: "Was it forged? Check what the service made of it.", hint: "There's a button in the details flyout.", target: "action:headers", why: "Signed by the tenant, SCL 1, no verdict. Nothing was forged, so nothing tripped. A clean result proves who sent it, and here the real mailbox did. Now the question moves from the message to the mailbox." },
    { id: "audit", ask: "Message trace can't tell you what happened inside a mailbox. Go to where actions are recorded.", hint: "Compliance, in the menu.", target: "menu:audit", why: "Trace follows the message. Audit follows the actions. The search is already scoped to Pavel, for this week." },
    { id: "rule", ask: "Something was set up before that reply was sent. Open it.", hint: "Read the times, the names and the IP addresses.", target: "row:a-new", why: "Monday, 02:51, from an address that isn't the office. A rule named with two dots, so it's nearly invisible in a list. Anything mentioning invoice, remittance or bank gets moved to RSS Feeds and marked read. Nobody opens RSS Feeds." },
    { id: "send", ask: "Tie the rule to the reply. Open the action that sent it.", hint: "Same IP address as the rule, later on.", target: "row:a-send", why: "The same 203.0.113.141 sent the bank-change reply fourteen hours later. Whoever made the rule wrote the email, and the rule hid the supplier's answers from Pavel while they did it." },
    { id: "box", ask: "Someone may still be in there. Go to the mailbox.", hint: "Recipients, at the top of the menu.", target: "menu:mailboxes", why: "You've got the how. Now stop it, then look at what else they read." },
    { id: "who", ask: "Open the account that was taken over.", hint: "Whose mailbox made the rule?", target: "row:m-ps", why: "Two inbox rules, and only one of them is Pavel's." },
    { id: "signout", ask: "End whatever is open on that account.", hint: "The buttons in the flyout.", target: "action:signout", why: "Sign out first, so the attacker can't simply remake the rule. Then reset the password, delete the rule, and read what the mailbox read while they were in it." },
  ],
  traps: {
    "row:t-1": "That's the supplier's genuine invoice. The problem came after it.",
    "row:t-3": "Quarantined spam about a tractor. The filter did its job on this one.",
    "row:a-old": "A catalogue rule from March, from the office IP, with a plain name. That one's Pavel.",
    "row:a-log": "The office address at 08:30 on a working day. That's the real person starting work.",
    "row:m-ob": "Ona received the reply. Their mailbox has no rules, and nobody took it over.",
    "action:release": "Reporting it as junk teaches the filter nothing useful: this was real mail from a real mailbox. And you still don't know how.",
    "action:wipe": "Deleting the mailbox destroys your evidence and stops a real employee working. End the sessions first.",
    "action:signoutob": "Ona's account isn't the one that was taken over.",
  },
  lesson: "A hijacked thread passes every check, because a real mailbox sent it. When the message looks clean, leave the message and open the audit log: the inbox rule, its name, its address and its timing tell you what the trace can't.",
};

export const EXCHANGE_ONLINE_SECURITY: RoomExperience = {
  roomId: "exchange-online-security",
  codename: "Operation Reply All",
  theme: "replyall",
  handler: { name: "Sefa Mensah", role: "Mail Security Engineer, Thistledown Seed Co-op" },
  briefing: [
    "Thistledown Seed Co-op. 212 mailboxes, 4,000 farmers, and every order, invoice and payment runs through email.",
    "This spring's seed money went to the wrong bank account, and the request sat on a real thread, with a real colleague's name on it.",
    "Sefa Mensah has seen this before: there was no virus and no alarm. Mail was all it took.",
    "Learn the road every message takes, how a domain proves itself, and where to look when the mail itself looks clean.",
  ],
  mission: "Walk a message through the gateway, sort what each layer catches, read the seals, defuse the headers, hold back bad inbox rules, work a hijacked thread in the console, then close the graded case.",
  estimate: "~45 min",
  look: { primary: "#34d399", secondary: "#fbbf24", warn: "#f87171" },
  scene: "facilitymail",
  layout: "facility",
  stations: [
    {
      id: "mailbox",
      label: "The Mailbox",
      topic: "The road of an inbound message · MX · EOP · Defender for Office 365 · SCL · ZAP",
      tagline: "What stands between the internet and the inbox?",
      building: "control",
      taskIds: ["exch-sec-r1"],
    },
    {
      id: "seal",
      label: "The Seal",
      topic: "SPF, DKIM and DMARC · alignment · reading Authentication-Results",
      tagline: "Who really sent this?",
      building: "office",
      taskIds: ["exch-sec-r2", "exch-sec-q1"],
    },
    {
      id: "rule",
      label: "The Silent Rule",
      topic: "BEC · inbox rules · the audit operations · the analyst's workflow",
      tagline: "Clean mail, wrong hands",
      building: "lab",
      taskIds: ["exch-sec-r3", "exch-sec-q2", "exch-sec-q3"],
    },
    {
      id: "wire",
      label: "The Wire",
      topic: "Reading one suspicious message to the end",
      tagline: "Stop it before it's paid",
      building: "ticket",
      taskIds: ["exch-sec-la1", "exch-sec-f1"],
      boss: true,
    },
  ],
  personas: {
    "exch-sec-q1": { name: "Sefa Mensah", role: "Mail Security Engineer", line: "Two passes and a fail. Read me that header." },
    "exch-sec-q2": { name: "Sefa Mensah", role: "Mail Security Engineer", line: "Everything passed. So what's wrong with it?" },
    "exch-sec-q3": { name: "Sefa Mensah", role: "Mail Security Engineer", line: "The search came back empty. That isn't the end of it." },
    "exch-sec-la1": { name: "Sefa Mensah", role: "Mail Security Engineer", line: "Finance has this one open right now. Read the record." },
    "exch-sec-f1": { name: "Sefa Mensah", role: "Mail Security Engineer", line: "One more thing for the mail-flow team." },
  },
  briefings: {
    // ── Reading 1: the road in ──
    "exch-sec-r1": [
      {
        kind: "pathway",
        title: "Walk the Message In",
        prompt: "An order from a farmer in the valley is on its way to orders@thistledown.example. Sefa traces a line on the whiteboard and hands you the pen. Take it from the sender's server to the inbox, one hop at a time, without skipping a checkpoint.",
        goal: "Reach the mailbox through every inspection point, in order.",
        nodes: [
          { id: "send", label: "Sending server", sub: "The farmer's mail host", x: 10, y: 50 },
          { id: "dns", label: "DNS lookup", sub: "MX record", x: 28, y: 22 },
          { id: "eop", label: "EOP", sub: "Included filtering", x: 46, y: 50 },
          { id: "mdo", label: "Defender for Office 365", sub: "Paid layer", x: 66, y: 22 },
          { id: "box", label: "Mailbox", sub: "orders@", x: 88, y: 50 },
          { id: "quar", label: "Quarantine", sub: "Held for review", x: 66, y: 80 },
          { id: "user", label: "A user's desktop", sub: "On-prem PC", x: 28, y: 80 },
        ],
        edges: [["send", "dns"], ["send", "user"], ["send", "eop"], ["dns", "eop"], ["eop", "mdo"], ["eop", "quar"], ["eop", "box"], ["mdo", "box"], ["mdo", "quar"]],
        route: ["send", "dns", "eop", "mdo", "box"],
        notes: {
          dns: "The sender asks DNS who takes mail for this domain. The MX record points to Microsoft's protection service, so the road runs through there.",
          eop: "Exchange Online Protection is the first stop for all inbound mail: connection filtering, anti-spam, anti-malware and the authentication checks.",
          mdo: "If the organisation licenses it, Safe Attachments detonates files in a sandbox and Safe Links rewrites URLs to check them when clicked.",
          box: "Delivered. It isn't over, though: Zero-hour Auto Purge can still pull this message out later if it's reclassified.",
        },
        traps: {
          user: "Mail doesn't go to a desktop. Mail goes to whichever host the domain's MX record names.",
          quar: "This order is clean. Quarantine is where a message goes when it's held, not a stop on the normal road.",
          eop: "Not yet. A sending server can't know where to go until DNS has told it.",
          box: "Too soon. Delivery comes last, and there's still a layer to pass on this tenant.",
        },
        lesson: "A message has one road: DNS tells the sender where, EOP filters it, Defender for Office 365 inspects what's left, and only then does it land. Each stop leaves a trace you can read later.",
      },
      {
        kind: "rush",
        title: "Which Layer Caught It?",
        prompt: "Sefa reads out the week's catches at speed. For each one, call the layer: the filtering every tenant gets, or the paid layer on top.",
        seconds: 60,
        target: 9,
        trueLabel: "EOP",
        falseLabel: "Defender for Office 365",
        cards: [
          { id: "a", text: "An IP on a known-bad reputation list was refused at connection", answer: true, why: "Connection filtering is part of EOP." },
          { id: "b", text: "A PDF was opened in a sandbox VM and tried to run a script", answer: false, why: "Detonating an attachment is Safe Attachments." },
          { id: "c", text: "A link was checked at the moment a user clicked it", answer: false, why: "Time-of-click checking is Safe Links." },
          { id: "d", text: "A message got a Spam Confidence Level of 7", answer: true, why: "The SCL score comes from EOP's anti-spam." },
          { id: "e", text: "An attachment matched a known malware signature", answer: true, why: "Signature scanning is EOP's anti-malware." },
          { id: "f", text: "A newsletter got a Bulk Complaint Level of 6", answer: true, why: "BCL comes from EOP's bulk filtering." },
          { id: "g", text: "A sender's display name imitated the co-op's chairperson", answer: false, why: "Impersonation protection belongs to the anti-phishing features of the paid layer." },
          { id: "h", text: "A URL in a Teams message was rewritten", answer: false, why: "Safe Links covers Teams messages too." },
          { id: "i", text: "A delivered message was pulled from inboxes after being reclassified", answer: true, why: "Zero-hour Auto Purge comes with EOP, and it works after delivery." },
          { id: "j", text: "An SPF check failed for an inbound message", answer: true, why: "The email authentication checks run in EOP." },
          { id: "k", text: "An unknown file behaved badly in a detonation environment", answer: false, why: "Unknown files are the point of a sandbox: signatures need something already known." },
          { id: "l", text: "A marketing blast was filed by its bulk score", answer: true, why: "Bulk filtering is included in EOP." },
        ],
        lesson: "EOP is what's known: reputation, signatures, scores and authentication. Defender for Office 365 watches behaviour: what a file does and where a link goes at click time. Knowing the layer tells you which report to open.",
      },
    ],
    // ── Reading 2: the seals ──
    "exch-sec-r2": [
      {
        kind: "simulate",
        title: "Check the Seals",
        prompt: "Four messages reach Thistledown, all showing a From: address at harrowfield-seed.example. Run the three checks for each and see which ones hold.",
        checks: [
          { name: "SPF", question: "Is the connecting server listed in the envelope sender domain's SPF record?" },
          { name: "DKIM", question: "Is there a valid signature on the message?" },
          { name: "DMARC", question: "Did a passing check come from the same domain as the visible From:?" },
        ],
        scenarios: [
          { id: "own", label: "Harrowfield's own mail server", detail: "Envelope and signature both on harrowfield-seed.example, sent from its listed server.", results: ["pass", "pass", "pass"], why: ["The server is in the record.", "The signature verifies.", "Both match the visible From:."], verdict: "Everything lines up. It proves the domain sent it. It says nothing yet about whether that mailbox is in safe hands." },
          { id: "vendor", label: "A mailing vendor, no signature set up", detail: "Envelope domain is the vendor's own, and the server is listed there. The From: still shows Harrowfield.", results: ["pass", "fail", "fail"], why: ["SPF passed, for the vendor's domain.", "No signature at all.", "The only pass is for a different domain from the From:, so it doesn't align."], verdict: "SPF passed and DMARC still failed. A pass only counts toward DMARC if it's aligned with what the reader sees." },
          { id: "cloud", label: "Harrowfield's signed mail from a new host", detail: "A new server not yet in the SPF record, but the DKIM signature is Harrowfield's own.", results: ["fail", "pass", "pass"], why: ["The new server isn't listed.", "The signature verifies.", "DKIM passed and it matches the From:, so one aligned pass is enough."], verdict: "SPF failed and DMARC still passed. DMARC needs one aligned pass, not two." },
          { id: "forged", label: "A forged message from a rented server", detail: "No signature, the server isn't listed, and the From: is typed in by hand.", results: ["fail", "fail", "fail"], why: ["Not listed.", "Nothing to verify.", "Nothing passed, so nothing can align."], verdict: "A true spoof. What happens next is decided by the policy Harrowfield published, in p=." },
        ],
      },
      {
        kind: "defuse",
        title: "Defuse the Header",
        prompt: "Treasury is about to act on a batch of mail, and Sefa has the headers up. For each one, read the state and cut the wire that says what it really means. A wrong cut costs ten seconds.",
        device: "Payments release timer",
        seconds: 75,
        rounds: [
          {
            id: "none",
            state: "spf=fail  dkim=none  dmarc=fail action=none",
            wires: [
              { id: "pol", label: "Failed, and the domain's policy only monitors" },
              { id: "blk", label: "Failed, so it was rejected at the gateway" },
              { id: "ok", label: "Passed, because action=none means no problem" },
            ],
            cut: "pol",
            hint: "action= is what the policy told the receiver to do.",
            why: "action=none comes from p=none. The checks failed, and the message was delivered anyway. That's the header that catches analysts out.",
          },
          {
            id: "rej",
            state: "spf=fail  dkim=fail  dmarc=fail action=oreject",
            wires: [
              { id: "del", label: "Delivered to the inbox with a warning" },
              { id: "over", label: "A reject policy was treated as junk by the receiver" },
              { id: "good", label: "A DKIM failure only, so it's safe to read" },
            ],
            cut: "over",
            hint: "There's one extra letter in front of reject.",
            why: "oreject is Microsoft's override: the domain says reject, and the service sends the message to Junk instead. It didn't vanish, so a user can still find it there.",
          },
          {
            id: "dk",
            state: "spf=fail  dkim=pass header.d=harrowfield-seed.example  dmarc=pass  header.from=harrowfield-seed.example",
            wires: [
              { id: "spoof", label: "Spoofed, because SPF failed" },
              { id: "align", label: "Genuine domain: DKIM passed and aligned" },
              { id: "unk", label: "Unknown, because both checks must pass" },
            ],
            cut: "align",
            hint: "Compare header.d with header.from.",
            why: "One aligned pass is all DMARC needs. SPF often fails for honest reasons, so it doesn't decide anything alone.",
          },
          {
            id: "nope",
            state: "spf=pass  dkim=none  dmarc=bestguesspass  header.from=harrowfield-seed.example",
            wires: [
              { id: "pub", label: "The domain publishes no DMARC record" },
              { id: "strict", label: "The domain's policy is p=reject" },
              { id: "fail", label: "DMARC failed, so it's a spoof" },
            ],
            cut: "pub",
            hint: "A best guess is only needed when there's nothing to read.",
            why: "bestguesspass means no DMARC record exists, and the service estimated what one would have said. There's no policy behind it.",
          },
        ],
        lesson: "Read a header left to right, then read the action. Whether the checks passed and what the policy did about it are two separate facts, and a message can fail one and land anyway.",
      },
    ],
    // ── Reading 3: the rule, then the signature console ──
    "exch-sec-r3": [
      {
        kind: "intercept",
        title: "Hold Back the Rules",
        prompt: "Sefa has exported every inbox rule made at Thistledown this quarter. Each one drops toward the mailbox. Pull the ones built to hide something and let everyday tidying through.",
        protect: "the co-op's mailboxes",
        blockLabel: "Pull the rule",
        passLabel: "Leave it",
        seconds: 12,
        items: [
          { id: "a", text: "From: catalogues@ → Move to Catalogues", sub: "Name: Seed catalogues", bad: false, why: "A named sender, a sensible folder, and a name a person chose." },
          { id: "b", text: "Contains: invoice, payment → Delete", sub: "Name: .", bad: true, why: "Deleting anything about money, under a name that's barely there." },
          { id: "c", text: "All mail → Forward to a personal address outside the co-op", sub: "Name: backup", bad: true, why: "An external copy of every message is how mail leaves quietly." },
          { id: "d", text: "From: board@ → Mark as important", sub: "Name: Board mail", bad: false, why: "Flagging mail makes it more visible, not less." },
          { id: "e", text: "From: security@ or it@ → Move to Deleted Items", sub: "Name: tidy", bad: true, why: "Hiding IT and security mail keeps the victim from hearing about the problem." },
          { id: "f", text: "Contains: unsubscribe → Move to Newsletters", sub: "Name: Newsletters", bad: false, why: "Everyday tidying, and the mail is still there to read." },
          { id: "g", text: "Contains: wire, bank → Move to RSS Feeds, mark as read", sub: "Name: ..", bad: true, why: "A folder nobody opens, marked read so nothing shows up unread." },
          { id: "h", text: "From: harvest-rota@ → Move to Rota", sub: "Name: Rota", bad: false, why: "A named sender and a folder that says what it holds." },
          { id: "i", text: "Sent to: me only → Keep in Inbox", sub: "Name: Direct mail", bad: false, why: "It doesn't hide or move anything out of sight." },
        ],
        lesson: "A bad rule hides something from the person who owns the mailbox. Look at what it does and where it sends things: delete, forward outside, or bury in a folder no one reads, often under a name you can barely see.",
      },
      TRACE_LAB,
    ],
  },
};
