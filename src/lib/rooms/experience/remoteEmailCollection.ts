import type { RoomExperience } from "./types";
import type { HuntTable } from "./hunt";

// "Operation Quiet Forward" for the "remote-email-collection" room.
// Script: docs/campaign/87-remote-email-collection.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Sable Point Shipping (fictional), not the graded tasks' Northgate Logistics records.
// Signature: What Left, and How? MailItemsAccessed, Send, forwarding and delegate events tell
// different stories about one stolen session. A KQL hunt joins mail access to sign-ins on account
// and session, separates Bind rows from Sync rows and sizes what was read. Rooms 56 and 77 cover
// mail flow and forensics; this one is collection after a mailbox is taken.
// Game mix: codebreak + hunt + tune. Other labs: anatomy, match, queue, simulate, sort, trace.
//
// Lab data differs from the graded tasks: the stolen session is i.marchetti's, 9 Binds and one
// Sync, never r.iversen's 24 Binds (la1, f1); the REST record is a ticketed archive job, never an
// after-hours read from abroad (la1); no lab has a token searching for wire instructions (q1);
// each rule parameter is shown alone, never the forward, delete and stop combination (q2); the
// burst rule's numbers are not 24 in four minutes (la1); the delegates are a claims counsel on a
// shared mailbox and a migration account, never an assistant on an executive's mailbox (ac1);
// the owner's one read is from home in the evening, not the office by day (q3); the query lab
// hunts Set-Mailbox, never the rule operation or the two rule parameters (qf1); the response lab
// tries one move at a time and never shows an order (o1, q4).
// Sync is logged for desktop Outlook only, and readings r2 and r5 now say so.

const OWNER = "i.marchetti@sablepoint.example";
const COVER = "n.ferreira@sablepoint.example";
const OTHER = "r.haugen@sablepoint.example";
const REST = "Client=REST;Client=RESTSystem;;";
const OUTLOOK = "Client=Outlook;Microsoft Office/16.0";
const STOLEN = "9d04c7e6";

const MAIL_ACCESS: HuntTable = {
  name: "MailAccessEvents",
  note: "Saved function over OfficeActivity: Operation is MailItemsAccessed, one row per Bind message or Sync folder, with MailAccessType, InternetMessageId and SessionId (shortened) parsed out.",
  columns: ["TimeGenerated", "UserId", "MailboxOwnerUPN", "Logon_Type", "MailAccessType", "ParentFolder", "InternetMessageId", "ClientInfoString", "ClientIP", "SessionId"],
  rows: [
    ["10-29 03:20", OWNER, OWNER, "0", "Bind", "\\Inbox", "<61c0a1@sablepoint.example>", "Client=OWA", "198.51.100.212", "3be07d15"],
    ["11-03 02:38", OWNER, OWNER, "0", "Bind", "\\Inbox", "<7f2a01@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:38", OWNER, OWNER, "0", "Bind", "\\Inbox", "<7f2a02@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:39", OWNER, OWNER, "0", "Bind", "\\Inbox", "<7f2a03@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:40", OWNER, OWNER, "0", "Bind", "\\Inbox", "<7f2a04@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:40", OWNER, OWNER, "0", "Bind", "\\Inbox", "<7f2a05@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:41", OWNER, OWNER, "0", "Bind", "\\Inbox", "<7f2a06@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:43", OWNER, OWNER, "0", "Bind", "\\Bunker Invoices", "<7f2b01@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:43", OWNER, OWNER, "0", "Bind", "\\Bunker Invoices", "<7f2b02@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 02:44", OWNER, OWNER, "0", "Bind", "\\Bunker Invoices", "<7f2b03@sablepoint.example>", REST, "203.0.113.77", STOLEN],
    ["11-03 03:02", OWNER, OWNER, "0", "Sync", "\\Settlements", "-", OUTLOOK, "203.0.113.77", STOLEN],
    ["11-03 07:52", OWNER, OWNER, "0", "Sync", "\\Inbox", "-", OUTLOOK, "198.51.100.24", "11aa2f0c"],
    ["11-03 08:10", OWNER, OWNER, "0", "Bind", "\\Inbox", "<82d310@sablepoint.example>", OUTLOOK, "198.51.100.24", "11aa2f0c"],
    ["11-03 09:11", COVER, OWNER, "2", "Bind", "\\Settlements", "<82d344@sablepoint.example>", OUTLOOK, "198.51.100.24", "c2e81b40"],
    ["11-03 09:30", OTHER, OTHER, "0", "Sync", "\\Inbox", "-", OUTLOOK, "198.51.100.24", "66f0aa17"],
  ],
};

const SIGNINS: HuntTable = {
  name: "SigninLogs",
  note: "Interactive sign-ins. ResultType 0 is a success.",
  columns: ["TimeGenerated", "UserPrincipalName", "SessionId", "IPAddress", "Location", "AppDisplayName", "ResultType"],
  rows: [
    ["10-29 03:12", OWNER, "3be07d15", "198.51.100.212", "SG", "OfficeHome", "0"],
    ["11-03 02:31", OWNER, STOLEN, "203.0.113.140", "NL", "OfficeHome", "0"],
    ["11-03 07:50", OWNER, "11aa2f0c", "198.51.100.24", "DK", "Microsoft Office", "0"],
    ["11-03 09:05", COVER, "c2e81b40", "198.51.100.24", "DK", "Microsoft Office", "0"],
    ["11-03 09:28", OTHER, "66f0aa17", "198.51.100.24", "DK", "Microsoft Office", "0"],
  ],
};

const FOLDERS: HuntTable = {
  name: "FolderStats_CL",
  note: "Custom table IR loaded from Get-MailboxFolderStatistics for this one mailbox. Paths are matched to the audit log.",
  columns: ["FolderPath", "ItemsInFolder"],
  rows: [
    ["\\Inbox", "2412"],
    ["\\Bunker Invoices", "318"],
    ["\\Settlements", "1286"],
    ["\\Archive", "5120"],
    ["\\Deleted Items", "88"],
  ],
};

const SESSION_COLUMNS = ["TimeGenerated", "Operation", "ClientIP", "ClientInfoString", "Detail"];
const SESSION_ROWS = [
  ["11-03 02:31", "UserLoggedIn", "203.0.113.140", "-", "OfficeHome sign-in, ResultStatus Succeeded"],
  ["11-03 02:38", "MailItemsAccessed", "203.0.113.77", REST, "Bind, \\Inbox, 6 messages"],
  ["11-03 02:52", "New-InboxRule", "203.0.113.77", "Client=OWA", "Name: . | RedirectTo: settlements@sab1epoint.example | SubjectContainsWords: remit | MarkAsRead: True"],
  ["11-03 03:02", "MailItemsAccessed", "203.0.113.77", OUTLOOK, "Sync, \\Settlements"],
  ["11-03 03:20", "Send", "203.0.113.77", "Client=OWA", "Subject: RE: MV Kestrel Reach DA, revised remit-to"],
  ["11-03 03:24", "HardDelete", "203.0.113.77", "Client=OWA", "Same subject, purged from Recoverable Items"],
  ["11-03 03:31", "UpdateFolderPermissions", "203.0.113.77", "Client=OWA", "\\Settlements, Reviewer granted to t.brandt"],
];

export const REMOTE_EMAIL_COLLECTION: RoomExperience = {
  roomId: "remote-email-collection",
  codename: "Operation Quiet Forward",
  theme: "quietforward",
  handler: { name: "Hamid Nyberg", role: "Mail Forensics Analyst, Sable Point Shipping" },
  briefing: [
    "Sable Point Shipping. 240 people, nine bulk carriers, and a settlements desk that moves port money every Friday.",
    "A port agent in Santos has just asked why the remit-to on MV Kestrel Reach's disbursement account changed. Nobody at Sable Point changed it.",
    "The mail came from i.marchetti's real mailbox, so Hamid Nyberg, Mail Forensics Analyst, is treating that session as stolen.",
    "Hamid needs the next part from you: what left that mailbox, how it left, and how much was read.",
  ],
  mission: "Tell where each kind of mail theft leaves evidence, read a mail access record, learn what each rule parameter does to one message, join mail access to sign-ins, size what one session read, tune a burst rule, test each response move alone, weigh delegates, and hunt the forward that no rule shows.",
  estimate: "~55 min",
  look: { primary: "#7dcfb6", secondary: "#f79d65", warn: "#f25c78" },
  scene: "facilityquietforward",
  layout: "facility",
  stations: [
    {
      id: "audit",
      label: "The Mailbox Audit",
      topic: "T1114 sub-techniques · what attackers want from mail · MailItemsAccessed fields · audit event names",
      tagline: "Somebody else has the key",
      building: "archive",
      taskIds: ["remc-r1", "remc-r2", "remc-q1"],
    },
    {
      id: "rule",
      label: "The Quiet Rule",
      topic: "What each inbox rule parameter does · mailbox-level forwarding · whether mail really left",
      tagline: "Access that outlasts the login",
      building: "office",
      taskIds: ["remc-r3", "remc-q2", "remc-m1"],
    },
    {
      id: "session",
      label: "One Session",
      topic: "Joining mail access to sign-ins · Bind and Sync · sizing a read · response moves",
      tagline: "Ten rows, and how many messages?",
      building: "lab",
      taskIds: ["remc-r4", "remc-la1", "remc-o1"],
    },
    {
      id: "cover",
      label: "The Cover Story",
      topic: "Delegates, migrations and service accounts · proving a relationship · benign true positives",
      tagline: "Most mailbox access is fine",
      building: "reception",
      taskIds: ["remc-r5", "remc-ac1", "remc-q3"],
    },
    {
      id: "left",
      label: "What Left",
      topic: "Writing a forwarding hunt · the origin of a session · what a reset leaves running",
      tagline: "Every way out gets its own line",
      building: "vault",
      taskIds: ["remc-qf1", "remc-f1", "remc-q4"],
      boss: true,
    },
  ],
  personas: {
    "remc-q1": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "Name the technique before it goes in the ticket." },
    "remc-q2": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "Read the whole rule, not only the address." },
    "remc-m1": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "The new analyst is asking what these terms mean. Sort it out." },
    "remc-la1": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "This one came in from a sister company's SIEM. Same questions." },
    "remc-o1": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "Legal wants the running order on one page." },
    "remc-ac1": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "One record, one ticket reference. Your verdict." },
    "remc-q3": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "The queue is long. What does this one deserve?" },
    "remc-qf1": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "Detection engineering wants this written down so it runs daily." },
    "remc-f1": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "I need one value to pull the whole chain." },
    "remc-q4": { name: "Hamid Nyberg", role: "Mail Forensics Analyst", line: "Someone asks what the reset actually did. Answer carefully." },
  },
  briefings: {
    // ── Reading 1: what the attacker wants once inside ──
    "remc-r1": [
      {
        kind: "sort",
        title: "Where Does the Evidence Live?",
        prompt: "Tuesday morning, and Hamid has a list of mail thefts from past cases at other shipping firms. Before anyone opens a log, decide what kind of collection each one is, because that tells you which team's data to ask for.",
        primer: {
          title: "Ask where the data sat when it was taken",
          points: [
            "ATT&CK calls this family **T1114 Email Collection**. Its sub-techniques split by how the mail was reached.",
            "If the data sat on a machine, the evidence is endpoint telemetry: processes and file reads.",
            "If it was reached through a service over the network, the evidence is that service's own audit log.",
            "A copy that moves by itself, with nobody reading live, is a third case: look at what was configured.",
          ],
          example: {
            label: "The same question on a set of tender documents",
            lines: [
              "Copied off a laptop's disk by a tool on that laptop: EDR file events.",
              "Opened in a browser from a SharePoint library, from anywhere: the cloud audit log.",
              "Same documents, two thefts, and two different teams hold the proof.",
            ],
          },
        },
        buckets: [
          { id: "local", label: "T1114.001 Local: mail files on a machine" },
          { id: "remote", label: "T1114.002 Remote: pulled over the network from the mail server" },
          { id: "rule", label: "T1114.003 Forwarding Rule: mail moves on by itself" },
        ],
        items: [
          { id: "a", text: "A .pst archive is copied off a Finance laptop by a tool running on it", bucket: "local", why: "The mail is a file on a disk. Endpoint file events show the read, and the mail server never hears about it." },
          { id: "b", text: "A Thunderbird profile folder is zipped on a compromised workstation", bucket: "local", why: "A local profile is mail on disk. The evidence is the archive tool's process and file activity." },
          { id: "c", text: "An IMAP client in another country pulls a broker's folders overnight", bucket: "remote", why: "IMAP is the account's own remote access. No Sable Point device is involved, so only the service's audit trail sees it." },
          { id: "d", text: "A browser on Outlook on the web reads a director's mail from a rented server", bucket: "remote", why: "A browser session on the mail service is remote access too. The victim's laptop can be switched off the whole time." },
          { id: "e", text: "A new phone mail app appears on a chartering manager's account", bucket: "remote", why: "A synced client is a remote channel. Nothing happens on any machine you manage." },
          { id: "f", text: "An inbox rule starts sending bank-detail mail to a lookalike domain", bucket: "rule", why: "Nobody has to read anything live. The rule moves the mail, so ATT&CK gives it its own sub-technique." },
          { id: "g", text: "A stolen admin account adds an organisation-wide rule that copies all mail", bucket: "rule", why: "Same idea at a larger scale: a configured rule moves the mail with nobody connected." },
        ],
      },
      {
        kind: "match",
        title: "What Is a Mailbox Worth?",
        prompt: "A mailbox holds more than conversations. Match what an intruder finds in i.marchetti's folders to what it buys them next.",
        pairs: [
          { id: "a", left: "Months of replies between Settlements and a port agent", right: "A writing style good enough to fake the next reply", why: "Intelligence gathering. Fraud works when the message sounds like the person, and old mail teaches exactly that." },
          { id: "b", left: "A live thread about a disbursement account due Friday", right: "A payment to step into, with changed bank details", why: "Direct fraud. The attacker doesn't start a conversation, they join one that is already trusted." },
          { id: "c", left: "An old password reset link and a VPN profile", right: "A way into other systems", why: "Credential harvesting. Mailboxes keep what other systems sent them, sometimes for years." },
          { id: "d", left: "A director's calendar and contact list", right: "A map of who to target next", why: "Reconnaissance. It shows who approves payments, who is travelling, and who reports to whom." },
        ],
      },
    ],
    // ── Reading 2: the audit record ──
    "remc-r2": [
      {
        kind: "anatomy",
        title: "Read a Mail Access Record",
        prompt: "Before the case records, Hamid hands you a record that is supposed to be there: last night's mail archive job, running under ticket CHG-5102. Scan each field. These are the fields the rest of this room depends on.",
        source: "Unified Audit Log · MailItemsAccessed · archive job",
        fields: [
          { key: "Operation", value: "MailItemsAccessed", label: "What happened", note: "Mail data was reached by a mail protocol or client. Exchange writes it whether or not anyone actually read the message." },
          { key: "RecordType", value: "50" },
          { key: "UserId", value: "svc-archive@sablepoint.example", label: "Who acted", note: "The account making the request." },
          { key: "MailboxOwnerUPN", value: "p.dahl@sablepoint.example", label: "Whose mailbox", note: "Whose mail it is. It only differs from UserId when somebody else is reading." },
          { key: "LogonType", value: "1", label: "Whose access", note: "0 is Owner, 1 is Admin, 2 is Delegate. An app acting for users through impersonation shows as Admin. None is bad on its own: check it against a relationship you can prove." },
          { key: "ClientIPAddress", value: "198.51.100.31", label: "From where", note: "The address the request came from. Here, the archive server's egress." },
          { key: "ClientInfoString", value: REST, label: "Made by what", note: "REST with no mail client named: code called the API. The archive tool works this way, and so does anything else that holds a token." },
          { key: "MailAccessType", value: "Bind", label: "In what shape", note: "Bind is one message, reached by its own request. The other value, Sync, is a whole folder pulled at once: Exchange logs that for desktop Outlook as one event on the folder." },
          { key: "OperationCount", value: "2", note: "Exchange rolls Binds from a 2-minute window into one record, so one record can hold several messages." },
          { key: "Folders[0].FolderItems[0].InternetMessageId", value: "<3c91f0@sablepoint.example>", label: "Which message", note: "Each Bind names its message. A Sync doesn't, which matters when you size a read." },
          { key: "SessionId", value: "e07b31c4d2a9458fb6c1", label: "Which session", note: "Shared by every record from one authenticated session: the sign-in, the mail access, any rule it creates." },
        ],
        summary: "This record is fine: a known service account, a change ticket, the archive server's address. The REST client string alone settles nothing either way, because it only says code made the request. Read who acted, on whose mailbox, from where, in what shape and in which session, then decide.",
      },
      {
        kind: "codebreak",
        title: "Four Words the Log Uses",
        prompt: "MailItemsAccessed tells you what was read. It says nothing about what was sent, destroyed or handed over. Hamid wants you fluent in the other words before you open a real session. Break each one from its clue.",
        primer: {
          title: "Exchange names these events plainly",
          points: [
            "Mailbox audit logs one named action per thing done. Each family tells a different story: reading, sending, destroying, granting.",
            "The action name is usually a plain verb or a right, written as one word.",
            "Who did it matters too: some actions are only logged for an owner, others only for delegates and admins.",
          ],
          example: {
            label: "Three names that show the pattern",
            lines: [
              "`MoveToDeletedItems`: a message was deleted and went to Deleted Items.",
              "`SoftDelete`: it was deleted from there and went to Recoverable Items.",
              "`UpdateInboxRules`: an inbox rule was added, removed or changed.",
            ],
          },
        },
        rounds: [
          { id: "send", clue: "One word. The owner of a mailbox sends, replies to or forwards a message.", answer: "Send", why: "Send records the outgoing message with its subject. A stolen session is logged as the owner, so the session and client string have to show it wasn't the person." },
          { id: "sendas", clue: "Six letters. Another user sends mail that looks as if the owner wrote it, with no trace of the real sender for the recipient.", answer: "SendAs", why: "SendAs is logged for delegates and admins. SendOnBehalf is its open cousin: the recipient sees who sent it for whom." },
          { id: "hard", clue: "Ten letters. A message is purged from Recoverable Items, the last stop before it is gone.", answer: "HardDelete", why: "HardDelete after a fraud reply means somebody cleaned up. The record keeps the fact even though the message is gone." },
          { id: "full", clue: "Ten letters. The mailbox permission that lets another user open everything. An admin grants it, and the user's access then logs as Delegate.", answer: "FullAccess", why: "A user holding FullAccess, SendAs or SendOnBehalf signs in as a delegate. So every Delegate record leads to one question: who granted that, and when?" },
        ],
        lesson: "Reading, sending, destroying and granting each have their own record. MailItemsAccessed alone answers only the first, so a mailbox case needs all four kinds of event laid side by side.",
      },
    ],
    // ── Reading 3: rules ──
    "remc-r3": [
      {
        kind: "simulate",
        title: "Follow One Message Through the Rule",
        prompt: "One incoming message, one setting at a time. Hamid built a test mailbox so you can watch what each parameter does to that message before you read one in a real record. Run every setting.",
        primer: {
          title: "A rule is a condition and an action",
          points: [
            "Exchange checks a mailbox's inbox rules in order for every message that arrives.",
            "A condition says which mail the rule fires on. An action says what happens to it.",
            "Rules are mailbox settings. They keep running with nobody signed in.",
          ],
          example: {
            label: "A harmless rule, read out loud",
            lines: [
              "`New-InboxRule -Name News -From news@portweekly.example -MoveToFolder News`",
              "Condition: mail from that sender. Action: move it to a folder.",
              "`Set-InboxRule` changes a rule that already exists.",
            ],
          },
        },
        checks: [
          { name: "No clean-up", question: "Is this rule free of any delete or move action?" },
          { name: "Company", question: "Does the message stay inside the company?" },
          { name: "Later rules", question: "Do the rules further down the list still run?" },
        ],
        scenarios: [
          { id: "fwd", label: "ForwardTo", detail: "New-InboxRule -Name Copy -ForwardTo ops@harbour-desk.example", results: ["pass", "fail", "pass"], why: ["No delete or move action here, and the original is delivered as usual.", "A copy goes to the other address, sent by this mailbox.", "Nothing stops the rules below."], verdict: "A copy leaves and the original stays. The copy shows this mailbox as the sender, so a reply comes back here, and that is one way an owner may notice." },
          { id: "red", label: "RedirectTo", detail: "New-InboxRule -Name Move -RedirectTo ops@harbour-desk.example", results: ["pass", "fail", "pass"], why: ["No delete or move action in this rule.", "It goes to the other address still showing the original sender.", "Nothing stops the rules below."], verdict: "A redirect keeps the original sender on the message, so it looks as if that sender wrote to the other address directly. Replies go to the original sender, not back through this mailbox, so the owner never sees that side of the conversation." },
          { id: "del", label: "DeleteMessage", detail: "New-InboxRule -Name Tidy -From news@portweekly.example -DeleteMessage $true", results: ["fail", "pass", "pass"], why: ["This is the delete action: the message moves to Deleted Items straight away, out of the Inbox, and can still be recovered from there.", "This rule on its own sends nothing anywhere.", "Nothing stops the rules below."], verdict: "A person might do this to newsletters. The parameter only matters by what it sits beside, so read every action in a rule together." },
          { id: "stop", label: "StopProcessingRules", detail: "New-InboxRule -Name First -From news@portweekly.example -MoveToFolder News -StopProcessingRules $true", results: ["fail", "pass", "fail"], why: ["This rule moved it to News, out of the Inbox.", "It went to a folder in the same mailbox.", "This rule matched, so the rules below are skipped for this message."], verdict: "Order is part of the logic. Any rule lower in the list never sees mail that matched this one." },
          { id: "key", label: "Keyword condition", detail: "New-InboxRule -Name Port -SubjectContainsWords demurrage -ForwardTo ops@harbour-desk.example", results: ["pass", "fail", "pass"], why: ["No delete or move action here, and the original is delivered as usual.", "Only mail with that word in the subject goes out. Everything else is left alone.", "Nothing stops the rules below."], verdict: "A narrow rule produces very little to notice and gets exactly the mail it wants. Narrow is deliberate, not harmless." },
          { id: "mbx", label: "Mailbox forwarding", detail: "Set-Mailbox -Identity p.dahl -ForwardingSmtpAddress ops@harbour-desk.example -DeliverToMailboxAndForward $true", results: ["pass", "fail", "pass"], why: ["No rule, so no rule action. With DeliverToMailboxAndForward set to true, the original stays too.", "Every message goes out, with no condition at all.", "No rule is involved, so the rule list is untouched."], verdict: "This isn't a rule. It sits on the mailbox itself, covers all mail, and doesn't show up as a rule operation in the audit log." },
        ],
      },
      {
        kind: "sort",
        title: "Did It Actually Leave?",
        prompt: "A rule existing doesn't prove mail left. Sable Point's other mailboxes have forwards too, and Hamid has to tell the insurer which ones lost data. Read each setup and decide where the mail ended up.",
        primer: {
          title: "Two different switches decide",
          points: [
            "The rule or forward says where mail should go. Tenant settings decide whether it may go outside.",
            "The outbound spam policy has an automatic forwarding setting: **Automatic - System-controlled**, **On** or **Off**.",
            "Automatic - System-controlled blocks external auto-forwarding by default. The sender gets a bounce, NDR 5.7.520.",
            "A remote domain setting can also block auto-forwarding to a domain, even when the policy says On.",
          ],
          example: {
            label: "A similar question at a building exit",
            lines: [
              "A parcel labelled for outside is not a parcel outside.",
              "Ask if a rule exists, then ask if the exit let it through.",
              "The second answer tells you what actually left.",
            ],
          },
        },
        buckets: [
          { id: "out", label: "Left the company" },
          { id: "stop", label: "Stopped at the exit" },
          { id: "in", label: "Never headed outside" },
        ],
        items: [
          { id: "a", text: "Rule forwards to an outside address. Policy: Automatic - System-controlled", bucket: "stop", why: "That setting blocks external auto-forwarding here, so the forward bounces with NDR 5.7.520. The bounce is a useful clue that someone tried." },
          { id: "b", text: "Rule forwards to an outside address. Policy: On", bucket: "out", why: "Somebody turned external forwarding on, so the mail went. Now you need to work out what matched." },
          { id: "c", text: "Mailbox forward to an outside address. Policy: Off", bucket: "stop", why: "Off blocks it, for a mailbox-level forward as well as for a rule." },
          { id: "d", text: "Rule forwards to an outside address. Policy: On. Remote domain blocks auto-forward", bucket: "stop", why: "The remote domain setting is a second gate. Both have to allow it." },
          { id: "e", text: "Rule forwards to a colleague's address in the same tenant. Policy: Off", bucket: "in", why: "The policy governs external forwarding. Internal forwarding isn't what it controls, though you may still care who got the mail." },
          { id: "f", text: "Agents group has its own policy set to On. A rule on an Agents mailbox forwards outside", bucket: "out", why: "A policy scoped to a group overrides the default for its members. Check which policy applies to this mailbox, not only the default." },
          { id: "g", text: "Mailbox forward to an outside address. Agents-group policy On, and the mailbox is in that group", bucket: "out", why: "Same scoped policy, different path. Every matching message left, because a mailbox forward has no condition." },
        ],
      },
    ],
    // ── Reading 4: the session ──
    "remc-r4": [
      {
        kind: "hunt",
        title: "What Left, and How?",
        prompt: "The Entra alert named one sign-in on i.marchetti's account, from 203.0.113.140 at 02:31. Hamid wants a number for the insurer: how much did that sign-in read? Build the hunt a line at a time. Every result you see is what that line really returns.",
        primer: {
          title: "A row is not a message",
          points: [
            "One account has many sessions, so join on **account and session** to get what one holder of the account did.",
            "With a stolen token, the sign-in and the mail reads can come from different addresses. The join has to survive that.",
            "A **Bind** row is one message, so counting Bind rows counts messages.",
            "A **Sync** row is a whole folder, with no list of messages. Assume every item in that folder was taken.",
          ],
          example: {
            label: "The same sum on a file server",
            lines: [
              "A contractor's session opened 3 files one by one, then copied one folder of 400.",
              "Log rows: 4. Files exposed: 403.",
              "So look up what each row stands for before you add it up.",
            ],
          },
        },
        language: "KQL",
        console: "Logs",
        start: "MailAccessEvents",
        goal: "three rows: each kind of access by that sign-in, and how many items each one exposes",
        tables: [MAIL_ACCESS, SIGNINS, FOLDERS],
        rungs: [
          {
            id: "box", ask: "Line 2: start from the mailbox, and keep everyone who touched it.",
            choices: [
              { id: "a", text: `| where UserId =~ "${OWNER}"`, why: "UserId is who acted. That drops n.ferreira's row, so anyone reading this mailbox from another account would disappear too.", apply: { op: "where", col: "UserId", test: "ieq", value: OWNER } },
              { id: "b", text: `| where MailboxOwnerUPN =~ "${OWNER}"`, right: true, why: "MailboxOwnerUPN is whose mail it is, so every reader stays in view, owner or not. r.haugen's mailbox is gone.", apply: { op: "where", col: "MailboxOwnerUPN", test: "ieq", value: OWNER } },
              { id: "c", text: '| where Logon_Type == "0"', why: "That keeps owners of every mailbox, r.haugen included, and drops the one Delegate row. Logon type says what kind of access, not which mailbox.", apply: { op: "where", col: "Logon_Type", test: "eq", value: "0" } },
            ],
          },
          {
            id: "join", ask: "Line 3: mail records can't say where a session began. Bring in the sign-ins.",
            choices: [
              { id: "a", text: "| join kind=inner SigninLogs on $left.UserId == $right.UserPrincipalName", why: "Account alone pairs every mail row with every sign-in that account ever made, so the rows multiply and nothing is tied to one session.", apply: { op: "join", table: "SigninLogs", left: "UserId", right: "UserPrincipalName" } },
              { id: "b", text: "| join kind=inner SigninLogs on $left.ClientIP == $right.IPAddress", why: "The attacker's rows vanished. They signed in from one address and read from another, while office rows paired with colleagues who share the same egress.", apply: { op: "join", table: "SigninLogs", left: "ClientIP", right: "IPAddress" } },
              { id: "c", text: "| join kind=inner SigninLogs on $left.UserId == $right.UserPrincipalName, SessionId", right: true, why: "Account and session together: every mail row now carries the sign-in that started it, and each row appears once. Different addresses don't matter here.", apply: { op: "join", table: "SigninLogs", left: "UserId", right: "UserPrincipalName", also: "SessionId" } },
            ],
          },
          {
            id: "who", ask: "Line 4: keep only what the alert's sign-in went on to do.",
            choices: [
              { id: "a", text: '| where ClientIP == "203.0.113.140"', why: "No rows. ClientIP is where each mail request came from, and this session never read mail from its sign-in address.", apply: { op: "where", col: "ClientIP", test: "eq", value: "203.0.113.140" } },
              { id: "b", text: '| where Location != "DK"', why: "That also keeps i.marchetti's real Singapore trip last week. Abroad isn't a verdict: the alert named a sign-in, so use it.", apply: { op: "where", col: "Location", test: "notin", value: ["DK"] } },
              { id: "c", text: '| where IPAddress == "203.0.113.140"', right: true, why: "IPAddress came from the sign-in side of the join, so this keeps the whole session wherever its reads came from. Ten rows left, all session 9d04c7e6.", apply: { op: "where", col: "IPAddress", test: "eq", value: "203.0.113.140" } },
            ],
          },
          {
            id: "shape", ask: "Line 5: separate the kinds of access. A folder must not be counted like a message.",
            choices: [
              { id: "a", text: "| summarize count() by SessionId", why: "One number, 10, adds nine messages to one folder. It's a count of rows, not of mail.", apply: { op: "summarize", by: ["SessionId"] } },
              { id: "b", text: '| where MailAccessType == "Bind"', why: "Tidy, and it throws away the biggest thing in the result. The Sync row is the part that hurts.", apply: { op: "where", col: "MailAccessType", test: "eq", value: "Bind" } },
              { id: "c", text: "| summarize count() by MailAccessType, ParentFolder", right: true, why: "Three rows: Binds per folder, plus one Sync. Now you can see that one row is a different kind of thing from the others.", apply: { op: "summarize", by: ["MailAccessType", "ParentFolder"] } },
            ],
          },
          {
            id: "size", ask: "Line 6: the audit log doesn't say how big a folder is. Bring in the table that does.",
            choices: [
              { id: "a", text: "| join kind=inner FolderStats_CL on $left.ParentFolder == $right.FolderPath", right: true, why: "Each folder now carries ItemsInFolder, which is what a Sync row needs. The audit log can't tell you this, so IR pulled it from the mailbox.", apply: { op: "join", table: "FolderStats_CL", left: "ParentFolder", right: "FolderPath" } },
              { id: "b", text: "| join kind=inner FolderStats_CL on ParentFolder", why: "The console refuses it: the right-hand table calls that column FolderPath. When names differ, use $left and $right.", apply: { op: "join", table: "FolderStats_CL", left: "ParentFolder", right: "ParentFolder" } },
              { id: "c", text: '| where MailAccessType == "Sync"', why: "That hides the nine messages read one by one, and still gives no size.", apply: { op: "where", col: "MailAccessType", test: "eq", value: "Sync" } },
            ],
          },
          {
            id: "show", ask: "Line 7: show only what the insurer's answer needs.",
            choices: [
              { id: "a", text: "| project MailAccessType, count_", why: "Without the folder and its size, a Sync row is just a 1.", apply: { op: "project", cols: ["MailAccessType", "count_"] } },
              { id: "b", text: "| project MailAccessType, ParentFolder, count_, ItemsInFolder", right: true, why: "Read it by type. Bind: count_ is the messages, 6 and 3. Sync: ItemsInFolder is the exposure, 1,286.", apply: { op: "project", cols: ["MailAccessType", "ParentFolder", "count_", "ItemsInFolder"] } },
              { id: "c", text: "| summarize count() by MailAccessType", why: "This counts rows of a summary: 2 and 1. It means nothing about mail.", apply: { op: "summarize", by: ["MailAccessType"] } },
            ],
          },
        ],
        expect: 3,
        lesson: "The answer for the insurer is 1,295 items, not 10: nine Binds you can name by InternetMessageId, plus all 1,286 in Settlements. A client that synced a folder can read it offline, so the log stops there and you assume the lot. In real KQL use dcount(InternetMessageId) for Binds, because a message read twice from a new address gets a second record.",
      },
      {
        kind: "trace",
        title: "One Session, Four Stories",
        prompt: "The same SessionId shows more than reads. Hamid pulled every record for session 9d04c7e6 from the audit log. Each question below has one row that answers it. Reading was only the first thing this session did.",
        lead: "Session 9d04c7e6 on i.marchetti, signed in 11-03 02:31 from 203.0.113.140.",
        steps: [
          { id: "persist", ask: "Which row keeps mail leaving after the attacker has gone?", source: "OfficeActivity, parsed · session 9d04c7e6", columns: SESSION_COLUMNS, rows: SESSION_ROWS, answer: 2, why: "A rule runs without a session. The redirect target, sab1epoint.example, is one character off the real domain, and the name is a single dot so it doesn't stand out in a list.", learned: "A rule redirects remit mail to a lookalike domain." },
          { id: "fraud", ask: "Which row is the fraud itself, leaving under i.marchetti's name?", source: "OfficeActivity, parsed · session 9d04c7e6", columns: SESSION_COLUMNS, rows: SESSION_ROWS, answer: 4, why: "Send is logged as the owner, so only the session shows it wasn't them. Message trace gives you who received it.", learned: "The revised remit-to mail was sent from this session." },
          { id: "grant", ask: "Which row gives someone a way in that doesn't depend on this session?", source: "OfficeActivity, parsed · session 9d04c7e6", columns: SESSION_COLUMNS, rows: SESSION_ROWS, answer: 6, why: "t.brandt can now read Settlements through a permission. Killing this session leaves that grant standing, so it needs its own check.", learned: "t.brandt was given Reviewer on Settlements." },
          { id: "size", ask: "Which row decides how much you have to tell the insurer was read?", source: "OfficeActivity, parsed · session 9d04c7e6", columns: SESSION_COLUMNS, rows: SESSION_ROWS, answer: 3, why: "A Sync of a whole folder outweighs any number of Binds. The client string changed too, because the session moved to a desktop mail client for the download.", learned: "Settlements was synced whole: assume every item." },
        ],
      },
      {
        kind: "tune",
        title: "Tune the Burst Rule",
        prompt: "Hamid wants a detection so the next stolen session doesn't wait for a port agent to phone. It scores each session on its Bind records. Set both bars, deploy, and catch all four sessions from past cases while letting people work.",
        primer: {
          title: "Volume alone, or speed alone, lies",
          points: [
            "Count how many different messages a session bound, and how fast. Both come from the Bind records.",
            "This rule fires only when a session passes **both** bars.",
            "People can read many messages slowly, or a few quickly. It takes both at once to stand out.",
            "A Sync doesn't enter this count: it's one folder event.",
          ],
          example: {
            label: "The same two bars on door badges",
            lines: [
              "A guard badges 60 doors a night, spread over eight hours: many, slow.",
              "A visitor rattles 4 doors in a minute: few, fast.",
              "A rule on 'many AND fast' passes both and catches someone trying every door.",
            ],
          },
        },
        eventColumn: "Session",
        dials: [
          { id: "msgs", label: "Different messages bound", short: "Messages", min: 5, max: 40, step: 1, start: 5 },
          { id: "rate", label: "Binds per minute", short: "Rate", unit: "/min", min: 1, max: 8, step: 0.5, start: 1 },
        ],
        mode: "all",
        events: [
          { id: "s1", label: "Settlements clerk's mailbox · from a hosting-provider address, 02:40", bad: true, values: { msgs: 38, rate: 6.5 } },
          { id: "s2", label: "Claims handler's mailbox · from a hotel network abroad, token issued to another device", bad: true, values: { msgs: 17, rate: 4.2 } },
          { id: "s3", label: "Port desk lead's mailbox · every Inbox message bound, oldest first", bad: true, values: { msgs: 90, rate: 12 } },
          { id: "s4", label: "Broker's mailbox · binds at a fixed 23-second gap for half an hour", bad: true, values: { msgs: 14, rate: 2.6 } },
          { id: "n1", label: "Clerk back from two weeks' leave", bad: false, values: { msgs: 64, rate: 0.4 } },
          { id: "n2", label: "Morning triage on the Settlements desk", bad: false, values: { msgs: 18, rate: 1.6 } },
          { id: "n3", label: "Broker clicking through search results", bad: false, values: { msgs: 9, rate: 3.4 } },
          { id: "n4", label: "Claims handler skimming one long thread", bad: false, values: { msgs: 11, rate: 3.0 } },
          { id: "n5", label: "Port desk clearing a shared mailbox", bad: false, values: { msgs: 22, rate: 2.2 } },
          { id: "n6", label: "Operations lead on a phone, between calls", bad: false, values: { msgs: 12, rate: 2.4 } },
          { id: "n7", label: "Owner opening a few mails", bad: false, values: { msgs: 5, rate: 1 } },
          { id: "n8", label: "svc-archive, nightly job under a change ticket", bad: false, values: { msgs: 400, rate: 30 } },
        ],
        goal: { catch: 4, maxFalse: 1 },
        lesson: "Round numbers fail here: a bar of 10 flags a fast reader, 15 misses the patient script, and a rate of 2 or 3 goes wrong too. The one false alarm you have to accept is svc-archive, and you remove that by naming the account in an exclusion after checking its ticket, never by raising the bars for everyone. These bars would not have fired on i.marchetti's session, 9 Binds in about 6 minutes, which is why origin and session checks still matter. A burst is a lead: it still needs the session, the origin and the baseline around it.",
      },
    ],
    // ── Ordering: one move at a time ──
    "remc-o1": [
      {
        kind: "simulate",
        title: "What Does Each Move Leave Running?",
        prompt: "This week's Friday payment is days away and every team is offering Hamid a fix. On a test tenant, try each move alone and see what it leaves running. Nobody has given you a running order yet: work out what each move depends on.",
        primer: {
          title: "Three things can still be alive",
          points: [
            "**New access:** someone with the password starts a new sign-in.",
            "**Existing access:** a session already issued, or a refresh token, keeps working until it ends or is revoked.",
            "**Automation:** a rule or forward runs on the server with no session at all.",
            "A move only counts for what it actually shut. Check all three after each one.",
          ],
          example: {
            label: "A leaking pipe in a building",
            lines: [
              "Mopping the floor doesn't stop the water.",
              "A new tap fitted to a burst pipe doesn't dry the floor either.",
              "Look at what each job leaves wet before you put them on a rota.",
            ],
          },
        },
        checks: [
          { name: "New access", question: "Can new sessions be refused?" },
          { name: "Existing access", question: "Is the session already issued dead?" },
          { name: "Automation", question: "Has mail stopped leaving by itself?" },
        ],
        scenarios: [
          { id: "block", label: "Block sign-in", detail: "Entra: Block sign-in set on i.marchetti, 09:00", results: ["pass", "fail", "fail"], why: ["Entra now refuses this account at the door.", "A token already in hand can still run until it expires.", "The rule doesn't need a sign-in."], verdict: "Fast, and it can be undone. It stops the situation growing, but nothing here has cleaned anything up yet." },
          { id: "reset", label: "Reset the password", detail: "Admin reset of i.marchetti's password, 09:00", results: ["pass", "fail", "fail"], why: ["The old password stops working for new sign-ins.", "09:40 and the REST client is still pulling mail. Its token was issued before the change, and nothing has told the service to stop honouring it.", "The rule doesn't care about the password."], verdict: "The ticket says fixed, while the log keeps moving. A new password on its own doesn't reach what is already running." },
          { id: "revoke", label: "Revoke sessions", detail: "Revoke all refresh tokens for i.marchetti, 09:00", results: ["fail", "pass", "fail"], why: ["Anyone holding the password signs straight back in.", "Refresh tokens are dead, and a live access token can't be renewed.", "The rule doesn't use a token."], verdict: "It works, and on its own it lasts minutes. This one and the password change cover each other's gap." },
          { id: "rule", label: "Remove the rule", detail: "Remove-InboxRule on i.marchetti's mailbox, 09:00", results: ["fail", "fail", "fail"], why: ["Nothing changed for sign-ins.", "The session is still live.", "Gone at 09:00, back at 09:06: the session that made it is still there and made it again."], verdict: "Removing persistence while its owner is still inside only tells them you noticed." },
          { id: "scope", label: "Pull the audit trail", detail: "Audit search on session 9d04c7e6, 09:00", results: ["fail", "fail", "fail"], why: ["Reading a log changes nothing.", "Reading a log changes nothing.", "The number you just measured is already out of date, because mail is still leaving."], verdict: "You need this, but a measurement only holds once the thing being measured has stopped moving." },
          { id: "tell", label: "Phone the port agents", detail: "Settlements calls every agent on file, 09:00", results: ["fail", "fail", "fail"], why: ["Nothing changed for sign-ins.", "The session is still live.", "The rule is still running."], verdict: "Which agents, and about which messages? Without the audit answer you either frighten all of them or miss the three that matter. When money may be moving, one urgent call can't wait, but the full notice needs the facts." },
        ],
      },
    ],
    // ── Reading 5: legitimate access ──
    "remc-r5": [
      {
        kind: "queue",
        title: "Prove the Relationship",
        prompt: "Now everyone at Sable Point is nervous, and the mailbox alerts are piling up. Most of these are people doing their jobs. Work Hamid's queue: a label, a name or a volume settles nothing, so look for what you can prove.",
        primer: {
          title: "Four questions, and one verdict name",
          points: [
            "Does the logon type match a relationship you can **verify**, in a ticket or grant record?",
            "Do the client string and address match a known device or service, and does a ticket, onboarding record or schedule explain the timing?",
            "Does the shape, Bind or Sync, volume and hour, fit what that role or tool would do?",
            "A **benign true positive** is a rule working correctly on real activity that turns out to be approved. Close it, and cite the proof.",
            "Contain when the activity ties to the confirmed session. Escalate when it is suspicious but not yet tied to it.",
          ],
          example: {
            label: "That verdict on another rule",
            lines: [
              "Alert: a new member was added to a privileged group.",
              "Real change, and exactly what the rule watches for. Change ticket CHG-3120 approves it.",
              "Rule was right, nothing is wrong, the ticket is the reason: benign true positive.",
            ],
          },
        },
        console: "SIEM · Mailbox alerts",
        actions: [
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "esc", label: "Escalate to IR", tone: "escalate" },
          { id: "con", label: "Contain the account", tone: "contain" },
        ],
        alerts: [
          { id: "a1", time: "09:42", severity: "Medium", rule: "Non-owner access to a shared mailbox", entity: "claims@sablepoint.example", fields: [{ k: "UserId", v: "o.castellan" }, { k: "LogonType", v: "2" }, { k: "MailAccessType", v: "Bind, 3 messages" }, { k: "ClientIP", v: "198.51.100.24 (office)" }], context: "o.castellan is Claims Counsel. Grant record CHG-4410 gave access to this shared mailbox last week for a cargo dispute.", answer: "btp", why: "A delegate, a current grant that names this mailbox, the office address, and a few messages a lawyer would open. The rule did its job, and CHG-4410 is your reason." },
          { id: "a2", time: "09:50", severity: "High", rule: "Non-owner access to a finance folder", entity: "i.marchetti, \\Settlements", fields: [{ k: "UserId", v: "t.brandt" }, { k: "LogonType", v: "2" }, { k: "MailAccessType", v: "Bind, 41 messages" }, { k: "ClientIP", v: "203.0.113.77" }], context: "No ticket exists. The Reviewer permission was granted at 03:31 by session 9d04c7e6. t.brandt works in Crewing.", answer: "con", why: "Delegate is the correct logon type here and it proves nothing: the grant came from the stolen session and the address matches it. Permission isn't the same as permitted." },
          { id: "a3", time: "10:05", severity: "Medium", rule: "High-volume mailbox access", entity: "svc-migrate@sablepoint.example", fields: [{ k: "LogonType", v: "1" }, { k: "MailAccessType", v: "Bind, 8,400 messages" }, { k: "ClientInfoString", v: REST }, { k: "ClientIP", v: "198.51.100.33" }], context: "Change CHG-5088 moves the Crewing department's mailboxes this week, 01:00 to 05:00. This run started at 01:02 from the migration server.", answer: "btp", why: "Huge numbers, off hours and a REST client all look alarming, and all of them fit a scheduled, ticketed migration tool from its own server." },
          { id: "a4", time: "10:12", severity: "High", rule: "High-volume mailbox access", entity: "e.lund@sablepoint.example", fields: [{ k: "LogonType", v: "0" }, { k: "MailAccessType", v: "Bind, 310 messages in 25 min" }, { k: "ClientInfoString", v: REST }, { k: "ClientIP", v: "198.51.100.177 (not seen before)" }], context: "e.lund is a marine superintendent. No ticket. 23:10 local time, and no script or tool is registered to this account.", answer: "esc", why: "A far smaller volume than the alert above, but from a person's own account, with no scheduled reason, and the address is new. Nothing ties it to the confirmed session yet, so escalate it with the session details." },
          { id: "a5", time: "10:20", severity: "Low", rule: "Mail access from outside the office network", entity: "m.okafor@sablepoint.example", fields: [{ k: "LogonType", v: "0" }, { k: "MailAccessType", v: "Bind, 1 message" }, { k: "ClientInfoString", v: "Client=OWA" }, { k: "ClientIP", v: "198.51.100.90 (home, 8 months)" }], context: "19:40 local time. The session's sign-in is clean, it created no rule, and it did nothing else.", answer: "btp", why: "The rule fired correctly on a person reading their own mail from their usual home address. Close it, and leave the rule as it is." },
          { id: "a6", time: "10:31", severity: "Medium", rule: "High-volume mailbox access", entity: "svc-backup2@sablepoint.example", fields: [{ k: "LogonType", v: "0" }, { k: "MailAccessType", v: "Bind, 96 messages" }, { k: "ClientInfoString", v: REST }, { k: "ClientIP", v: "203.0.113.205" }], context: "No service in the inventory has this name, no schedule mentions it, and the account was created on Sunday.", answer: "esc", why: "A svc- prefix is a naming habit, and anybody can create one. With no inventory entry, no job and an outside address, the name was the only thing it had going for it." },
        ],
      },
    ],
    // ── Query fill: the boss ──
    "remc-qf1": [
      {
        kind: "hunt",
        title: "The Way Out With No Rule",
        prompt: "The rule on i.marchetti is gone, but t.brandt's account was touched too, and Hamid has seen hunts stop at the first rule they find. There's a path out that no rule hunt will ever return. Build the query for it across the whole tenant.",
        primer: {
          title: "Every way out gets its own line",
          points: [
            "Mailbox-level forwarding is set with `Set-Mailbox`. It's a different operation from anything to do with rules.",
            "The `Parameters` column holds what a cmdlet was given, as text, so `has` and `contains` search it.",
            "If either of two parameters matters, write both, joined with `or`. Leave one out and you get a clean result that means nothing.",
            "`==` is exact and case-sensitive. `=~` ignores case.",
          ],
          example: {
            label: "Either right counts, on another cmdlet",
            lines: [
              "`OfficeActivity`",
              '`| where Operation =~ "Add-MailboxPermission"`',
              '`| where Parameters has "FullAccess" or Parameters has "ReadPermission"`',
            ],
          },
        },
        language: "KQL",
        console: "Logs",
        start: "OfficeActivity",
        goal: "two rows: every mailbox forward set to an outside SMTP address",
        tables: [
          {
            name: "OfficeActivity",
            note: "Office 365 audit records collected by the workspace.",
            columns: ["TimeGenerated", "OfficeWorkload", "Operation", "UserId", "ClientIP", "Parameters"],
            rows: [
              ["10-21 14:02", "Exchange", "Set-Mailbox", "adm-e.holm@sablepoint.example", "198.51.100.24", '[{"Name":"Identity","Value":"l.berg"},{"Name":"ForwardingSmtpAddress","Value":"smtp:l.berg@harbour-partners.example"},{"Name":"DeliverToMailboxAndForward","Value":"False"}]'],
              ["10-24 09:15", "Exchange", "Set-Mailbox", "adm-e.holm@sablepoint.example", "198.51.100.24", '[{"Name":"Identity","Value":"s.aune"},{"Name":"ForwardingAddress","Value":"Crewing Team"},{"Name":"DeliverToMailboxAndForward","Value":"True"}]'],
              ["10-27 11:30", "Exchange", "Set-Mailbox", "adm-e.holm@sablepoint.example", "198.51.100.24", '[{"Name":"Identity","Value":"j.moen"},{"Name":"ForwardingSmtpAddress","Value":""}]'],
              ["10-28 08:02", "Exchange", "Set-Mailbox", "adm-e.holm@sablepoint.example", "198.51.100.24", '[{"Name":"Identity","Value":"p.dahl"},{"Name":"RetentionPolicy","Value":"Default MRM Policy"}]'],
              ["10-30 16:44", "Exchange", "Set-CASMailbox", "adm-e.holm@sablepoint.example", "198.51.100.24", '[{"Name":"Identity","Value":"p.dahl"},{"Name":"ImapEnabled","Value":"False"}]'],
              ["11-02 17:05", "Exchange", "Set-MailboxAutoReplyConfiguration", "n.ferreira@sablepoint.example", "198.51.100.24", '[{"Name":"AutoReplyState","Value":"Enabled"}]'],
              ["11-02 17:20", "Exchange", "Set-InboxRule", "n.ferreira@sablepoint.example", "198.51.100.24", '[{"Name":"Identity","Value":"Port news"},{"Name":"MoveToFolder","Value":"News"}]'],
              ["11-03 03:40", "Exchange", "Set-Mailbox", "t.brandt@sablepoint.example", "203.0.113.77", '[{"Name":"Identity","Value":"t.brandt"},{"Name":"ForwardingSmtpAddress","Value":"smtp:crew.docs@mailbox-relay.example"},{"Name":"DeliverToMailboxAndForward","Value":"True"}]'],
              ["11-03 08:15", "SharePoint", "FileAccessed", "n.ferreira@sablepoint.example", "198.51.100.24", ""],
            ],
          },
        ],
        rungs: [
          {
            id: "wl", ask: "Line 2: keep the Exchange records.",
            choices: [
              { id: "a", text: '| where OfficeWorkload == "exchange"', why: "No rows. == is case-sensitive and the value is Exchange. An empty result here looks exactly like a clean tenant.", apply: { op: "where", col: "OfficeWorkload", test: "eq", value: "exchange" } },
              { id: "b", text: '| where OfficeWorkload == "Exchange"', right: true, why: "The SharePoint row is gone. Filtering the workload first keeps the rest of the query cheap and clear.", apply: { op: "where", col: "OfficeWorkload", test: "eq", value: "Exchange" } },
              { id: "c", text: '| where Workload == "Exchange"', why: "The console can't resolve it. Workload is the field's name in the raw audit record. This table calls it OfficeWorkload.", apply: { op: "where", col: "Workload", test: "eq", value: "Exchange" } },
            ],
          },
          {
            id: "op", ask: "Line 3: which operation sets a forward on the mailbox itself?",
            choices: [
              { id: "a", text: '| where Operation =~ "Set-InboxRule"', why: "That's an edit to a rule. A mailbox forward isn't a rule, so a rule search can't see it.", apply: { op: "where", col: "Operation", test: "ieq", value: "Set-InboxRule" } },
              { id: "b", text: '| where Operation contains "Mailbox"', why: "Too wide: Set-CASMailbox and the auto-reply cmdlet came along. Name the operation you mean.", apply: { op: "where", col: "Operation", test: "has", value: "Mailbox" } },
              { id: "c", text: '| where Operation =~ "Set-Mailbox"', right: true, why: "Five rows. Set-Mailbox does many jobs, so the parameters decide which rows matter.", apply: { op: "where", col: "Operation", test: "ieq", value: "Set-Mailbox" } },
            ],
          },
          {
            id: "param", ask: "Line 4: keep the rows that touched forwarding to an SMTP address.",
            choices: [
              { id: "a", text: '| where Parameters has "ForwardingSmtpAddress"', right: true, why: "Three rows. That parameter takes any SMTP address, inside or outside the company. One of the three has an empty value.", apply: { op: "where", col: "Parameters", test: "has", value: "ForwardingSmtpAddress" } },
              { id: "b", text: '| where Parameters contains "Forwarding"', why: "That also keeps ForwardingAddress, which points at an object inside the directory. Here that's the Crewing Team, so nothing went outside.", apply: { op: "where", col: "Parameters", test: "has", value: "Forwarding" } },
              { id: "c", text: '| where Parameters has "DeliverToMailboxAndForward"', why: "That parameter says whether the mailbox keeps a copy. It can sit next to a harmless internal forward, and a forward set without it is missed.", apply: { op: "where", col: "Parameters", test: "has", value: "DeliverToMailboxAndForward" } },
            ],
          },
          {
            id: "live", ask: "Line 5: one of those rows cleared a forward. Keep the rows that set one.",
            choices: [
              { id: "a", text: '| where ClientIP == "203.0.113.77"', why: "You chose by an answer you already had. A hunt has to work tomorrow, on an address nobody has met.", apply: { op: "where", col: "ClientIP", test: "eq", value: "203.0.113.77" } },
              { id: "b", text: '| where Parameters contains "smtp:"', right: true, why: "A real value starts with smtp:, so the cleared row with an empty value drops out. Two rows left.", apply: { op: "where", col: "Parameters", test: "has", value: "smtp:" } },
              { id: "c", text: '| where UserId has "adm-"', why: "That keeps admins and drops the user. Forwarding can be set by a user in their own mail settings, which is how this one was done.", apply: { op: "where", col: "UserId", test: "has", value: "adm-" } },
            ],
          },
          {
            id: "show", ask: "Line 6: show who, from where, and to where.",
            choices: [
              { id: "a", text: "| project TimeGenerated, UserId, ClientIP, Operation, Parameters", right: true, why: "Two rows. l.berg's is an admin's change with a ticket. t.brandt's came from the attacker's address, at 03:40.", apply: { op: "project", cols: ["TimeGenerated", "UserId", "ClientIP", "Operation", "Parameters"] } },
              { id: "b", text: "| summarize count() by UserId", why: "A count of 1 and 1 hides the destination, which is the one thing you came for.", apply: { op: "summarize", by: ["UserId"] } },
              { id: "c", text: "| project TimeGenerated, UserId", why: "When and who, but not from where or to where. You couldn't triage either row from this.", apply: { op: "project", cols: ["TimeGenerated", "UserId"] } },
            ],
          },
        ],
        expect: 2,
        lesson: "A hit is a lead, not a verdict: one of these two rows is approved. List every way mail can leave and give each its own condition, because a hunt that checks one path returns a clean-looking result that says nothing about the others. Mailbox audit also logs UpdateInboxRules when a rule is changed from a client, so check that as well. Then run the same thought on the tenant setting: did the mail get out?",
      },
    ],
  },
};
