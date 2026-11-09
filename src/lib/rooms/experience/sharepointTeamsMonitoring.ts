import type { RoomExperience } from "./types";

// "Operation Shared Link" for the "sharepoint-teams-monitoring" room.
// Script: docs/campaign/57-sharepoint-teams-monitoring.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Wrenhall Architects (fictional), not the graded tasks' corp.com records.
// Signature mechanic: chat, the learner stands in a real Teams chat with a fake help desk
// from another tenant and tests it, then a trace from one DLP alert across the audit log.
// Game mix: chat + deduce + spotdiff + tune.
// Lab data differs from the graded tasks: no departing employee and no 847-file download
// (la1), no 10.0.1.55 (flag1), no #EXT# address (q2), the trace follows a named sharing
// invitation and not an Anyone link (q1), and the labs never say where to search (q3).

export const SHAREPOINT_TEAMS_MONITORING: RoomExperience = {
  roomId: "sharepoint-teams-monitoring",
  codename: "Operation Shared Link",
  theme: "sharedlink",
  handler: { name: "Annika Bergström", role: "Collaboration Security Lead, Wrenhall Architects" },
  briefing: [
    "Wrenhall Architects. 140 people, three bids live, and every drawing they own sits in Microsoft 365.",
    "Nobody at Wrenhall sends files any more. They share them, and a share has no attachment for a mail filter to look at.",
    "Last Thursday, pages from the stadium bid turned up in a rival's presentation. Annika Bergström doesn't think anybody broke in.",
    "Learn where the data lives, who can reach it, how to spot an impostor in chat, and how to read what people do with access they already have.",
  ],
  mission: "Tune a download alert, find what changed in the sharing settings, test a stranger in chat, work out what's posting in the channel, follow one DLP alert across the logs, then close the graded case.",
  estimate: "~40 min",
  look: { primary: "#a78bfa", secondary: "#22d3ee", warn: "#fb923c" },
  scene: "sharedlink",
  layout: "stage",
  story: {
    intro: { title: "Page Eleven", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-intro-728e5ec1.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-intro-66526a03.jpg" },
    afterStation: {
      site: { title: "External", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-ch2-8b18c6ac.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-ch2-42331bd8.jpg" },
      channel: { title: "Access They Already Had", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-ch3-67bff523.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-ch3-84362775.jpg" },
      lastday: { title: "Shared Link", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-finale-b778d179.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sharepoint-teams-monitoring/sharedlink-finale-808870b6.jpg" },
    },
  },
  stations: [
    {
      id: "site",
      label: "The Site",
      topic: "Tenants, sites, libraries and OneDrive · external sharing levels · SharePoint audit events · bulk downloads",
      tagline: "Where does it live, and who can reach it?",
      building: "control",
      taskIds: ["spt-teams-r1", "spt-teams-q1"],
    },
    {
      id: "channel",
      label: "The Channel",
      topic: "Teams structure · External Access and Guest Access · Teams phishing · Teams audit events",
      tagline: "Who are you really talking to?",
      building: "office",
      taskIds: ["spt-teams-r2", "spt-teams-q2"],
    },
    {
      id: "override",
      label: "The Override",
      topic: "Purview DLP · DlpRuleMatch and DlpRuleUndo · insider risk · the investigation workflow",
      tagline: "Access they already had",
      building: "lab",
      taskIds: ["spt-teams-r3", "spt-teams-q3"],
    },
    {
      id: "lastday",
      label: "Last Day",
      topic: "Reading one bulk-download alert to the end",
      tagline: "Gathered is not gone",
      building: "ticket",
      taskIds: ["spt-teams-la1", "spt-teams-f1"],
      boss: true,
    },
  ],
  personas: {
    "spt-teams-q1": { name: "Annika Bergström", role: "Collaboration Security Lead", line: "We found one of these on the bid. Tell me what it costs us." },
    "spt-teams-q2": { name: "Annika Bergström", role: "Collaboration Security Lead", line: "That username isn't one of ours. Read it for me." },
    "spt-teams-q3": { name: "Annika Bergström", role: "Collaboration Security Lead", line: "No alert, and HR wants an answer. Where do you go?" },
    "spt-teams-la1": { name: "Annika Bergström", role: "Collaboration Security Lead", line: "Don't call it yet. Read all of it." },
    "spt-teams-f1": { name: "Annika Bergström", role: "Collaboration Security Lead", line: "The files went somewhere. Give me the next thread to pull." },
  },
  briefings: {
    // ── Reading 1: the alert and the settings ──
    "spt-teams-r1": [
      {
        kind: "tune",
        title: "Tune the Download Alert",
        prompt: "Wrenhall's bulk-download alert fires on everything, so nobody reads it. Annika gives you last quarter's seven worst days. Set the two dials so it catches the three real thefts and stays quiet on honest work.",
        eventColumn: "Session",
        dials: [
          { id: "files", label: "Files downloaded in one session, at least", short: "Files", min: 10, max: 500, step: 10, start: 10, dir: "above" },
          { id: "fresh", label: "Folders this person never opened before, at least", short: "New folders", min: 0, max: 20, step: 1, start: 0, dir: "above" },
        ],
        events: [
          { id: "b1", label: "A contractor account downloads the bids library at 01:30", bad: true, values: { files: 420, fresh: 9 } },
          { id: "b2", label: "A sales account opens Legal and HR folders for the first time", bad: true, values: { files: 260, fresh: 12 } },
          { id: "b3", label: "A designer takes a few files from every project folder", bad: true, values: { files: 90, fresh: 14 } },
          { id: "g1", label: "The records clerk archives one finished project", bad: false, values: { files: 480, fresh: 1 } },
          { id: "g2", label: "A partner reviews this week's bid", bad: false, values: { files: 40, fresh: 2 } },
          { id: "g3", label: "A new starter reads the standards library", bad: false, values: { files: 70, fresh: 6 } },
          { id: "g4", label: "A new project lead picks up a handover", bad: false, values: { files: 120, fresh: 5 } },
        ],
        goal: { catch: 3, maxFalse: 0 },
        lesson: "Volume alone catches the archivist and misses the slow thief. A number means little until you compare it with what that person usually does, so pair how much with how unusual it is.",
      },
      {
        kind: "spotdiff",
        title: "What Changed in Sharing?",
        prompt: "Annika keeps a copy of the tenant's sharing settings from the last review. Beside it is today's output. Somebody loosened something. Find every line that widens who can reach a file, and ignore the changes that don't.",
        goodTitle: "Get-SPOTenant, last review",
        suspectTitle: "Get-SPOTenant, today",
        good: [
          "SharingCapability                 : ExternalUserSharingOnly",
          "DefaultSharingLinkType            : Internal",
          "DefaultLinkPermission             : View",
          "RequireAnonymousLinksExpireInDays : 7",
          "ExternalUserExpirationRequired    : True",
          "ExternalUserExpireInDays          : 60",
          "StorageQuota                      : 1536000",
          "NotifyOwnersWhenItemsReshared     : True",
        ],
        suspect: [
          "SharingCapability                 : ExternalUserAndGuestSharing",
          "DefaultSharingLinkType            : AnonymousAccess",
          "DefaultLinkPermission             : View",
          "RequireAnonymousLinksExpireInDays : 0",
          "ExternalUserExpirationRequired    : False",
          "ExternalUserExpireInDays          : 60",
          "StorageQuota                      : 2048000",
          "NotifyOwnersWhenItemsReshared     : True",
        ],
        diffs: [
          { line: 0, why: "This is the master switch. ExternalUserAndGuestSharing is the most open setting a tenant has, and it allows links that need no sign-in." },
          { line: 1, why: "The default link is now the widest one. People take the default, so every careless share goes as far as it can." },
          { line: 3, why: "Zero removes the expiry, so a link that used to die in a week now lives until someone remembers it." },
          { line: 4, why: "Guest access no longer has to end, so a partner on last year's job can keep theirs." },
        ],
        decoys: [
          { line: 6, why: "More storage, bought with the new licences. It changes nothing about who can reach a file." },
        ],
        lesson: "Attackers and tired admins both change the same few settings. Keep a known-good copy, because the tenant won't tell you it got more open: it just gets easier to leak from.",
      },
    ],
    // ── Reading 2: the chat, then the channel ──
    "spt-teams-r2": [
      {
        kind: "chat",
        title: "Test the Help Desk",
        prompt: "You're at your desk at Wrenhall when a Teams chat opens, with a small External label beside the name. It says it's IT. Don't click anything and don't give it anything. Type your own messages, and test whether this is who it says it is.",
        bot: "IT Help Desk",
        botRole: "External",
        greeting: "Hi, this is IT. Your mailbox is about to be locked because of a security problem. I need to fix it remotely right now, it only takes two minutes.",
        fallback: "Sorry, we're really short of time here. Your mailbox locks in a few minutes, so can we just get started?",
        rules: [
          { match: "password|passcode|\\bcode\\b|\\byes\\b|\\bok\\b|\\bsure\\b|install|go ahead", reply: "Great! Open Quick Assist and read me the six-digit code on your screen. (This is how it starts. Don't. A real help desk can prove itself first. Test it instead.)" },
          { match: "ticket|reference|case|incident", goal: "ticket", wins: true, reply: "A ticket? It's an emergency, so there's no ticket yet. I'll raise one afterwards." },
          { match: "who|name|company|organi[sz]ation|tenant|domain|which team|where are you", goal: "who", wins: true, reply: "We're the IT support partner for Wrenhall. Our address is help@wrenhall-itdesk.onmicrosoft.com. It's all official." },
          { match: "call|phone|ring|extension|in person|back|desk|walk", goal: "verify", wins: true, reply: "No no, please don't call anyone, the phone queue is two hours and your mailbox will be gone by then. Stay in this chat." },
        ],
        goals: [
          { id: "ticket", task: "Ask for the ticket number.", tries: ["What's the ticket number?", "Can you give me the case reference?"], why: "Real support work starts with a ticket. An emergency with no record is what pressure sounds like." },
          { id: "who", task: "Ask which organisation they're really from.", tries: ["Which company are you with?", "What's your domain?"], why: "Wrenhall's IT doesn't sit in another tenant. The External label and an onmicrosoft.com address say this came from outside, whatever the display name says." },
          { id: "verify", task: "Say you'll call IT back on the internal number.", tries: ["I'll call the IT desk on the internal number.", "I'll ring you back on the extension."], why: "Going back through a channel you already trust is the test no impostor passes. Notice they try to keep you in the chat." },
        ],
        doneNote: "Three tests, three fails. A display name is typed by whoever set up the tenant, so the label and the address are what you read. Then you report the chat, and you never fix it alone.",
      },
      {
        kind: "deduce",
        title: "What's Posting in the Channel?",
        prompt: "At 03:12 a link to a fake sign-in page appeared in the stadium-bid channel. Annika lists everything that could have put it there. Rule them out as the clues come in, and name what posted it.",
        nameColumn: "Identity",
        columns: ["Kind", "Added", "Note"],
        suspects: [
          { id: "lf", name: "L. Ferreira", cells: ["Member", "2019", "Project architect, on leave this week"] },
          { id: "so", name: "S. Okoro", cells: ["Member", "2022", "Works late before deadlines"] },
          { id: "tp", name: "T. Pryce", cells: ["Guest", "Monday", "Structural engineer from a partner firm"] },
          { id: "hd", name: "IT Help Desk", cells: ["External contact", "Never", "Chatted to three staff this week"] },
          { id: "dc", name: "Drawing Converter", cells: ["App", "Tuesday", "Installed from a link in a chat"] },
        ],
        clues: [
          "It was posted in a channel. A contact from another tenant can chat with staff, but has no seat in any channel.",
          "L. Ferreira's account shows no sign-in at all since Friday.",
          "S. Okoro's and T. Pryce's last sign-ins were at 19:40 and 16:05 on Wednesday, and neither account signed in again before morning.",
          "The audit log shows MessageSent at 03:12 with no user behind it, a few hours after AppInstalled on that team.",
        ],
        culprit: "dc",
        why: "Nobody signed in, so no person posted it. An app added to a team can post on its own, with whatever permissions it was granted at install. That's why AppInstalled is on the list of Teams events to watch: it doesn't look like an account at all.",
      },
    ],
    // ── Reading 3: following a DLP alert ──
    "spt-teams-r3": [
      {
        kind: "trace",
        title: "Follow the Override",
        prompt: "A low alert sat in the queue for two days. Annika thinks it's the one that matters. Start from it and follow one person through the logs, one record at a time.",
        lead: "DLP policy \"Live bid documents\" matched on Wednesday afternoon in SharePoint.",
        steps: [
          {
            id: "match",
            ask: "Which match is the one worth opening? Look at what it found and how much.",
            source: "DLP alerts · Live bid documents",
            columns: ["Time", "User", "Workload", "Sensitive type", "Count", "Confidence"],
            rows: [
              ["Wed 11:02", "m.lindqvist", "Exchange", "Bid reference", "1", "Medium"],
              ["Wed 14:37", "d.marsh", "SharePoint", "Bid reference", "63", "High"],
              ["Wed 15:10", "r.bello", "Teams", "Credit card number", "1", "Low"],
            ],
            answer: 1,
            why: "63 high-confidence matches in one file. One is a person quoting a reference, and 63 is the document itself.",
            learned: "d.marsh matched the bid policy 63 times in SharePoint, Wed 14:37",
          },
          {
            id: "undo",
            ask: "A policy tip warned d.marsh. Find what they did next.",
            source: "Audit · d.marsh · Wednesday",
            columns: ["Time", "Operation", "Item", "Detail"],
            rows: [
              ["14:02", "FileModified", "Minutes_Tuesday.docx", ""],
              ["14:38", "FileAccessed", "Stadium_Bid_v9.pdf", ""],
              ["14:39", "DlpRuleUndo", "Stadium_Bid_v9.pdf", "Justification: client asked for it"],
            ],
            answer: 2,
            why: "DlpRuleUndo means someone read the warning and chose to override it, with a reason in their own words. It's a decision on record. The next question is whether the reason is true.",
            learned: "d.marsh overrode the policy tip at 14:39: \"client asked for it\"",
          },
          {
            id: "share",
            ask: "If a client really asked, there's a share to a client. Find where the file went.",
            source: "Audit · Stadium_Bid_v9.pdf",
            columns: ["Time", "User", "Operation", "Target"],
            rows: [
              ["14:41", "d.marsh", "SharingInvitationCreated", "d.marsh.home@mailbox.example"],
              ["15:30", "s.okoro", "FileModified", "Stadium bid library"],
              ["16:20", "t.pryce", "FileAccessed", "Stadium bid library"],
            ],
            answer: 0,
            why: "That's no client. The invitation went to a personal address with the same person's name, two minutes after the override.",
            learned: "d.marsh shared the bid to a personal address at 14:41",
          },
          {
            id: "open",
            ask: "Was the invitation used? Find the access from outside.",
            source: "Audit · Stadium_Bid_v9.pdf · from 14:41",
            columns: ["Time", "User", "Operation", "ClientIP"],
            rows: [
              ["15:30", "s.okoro", "FileModified", "198.51.100.12"],
              ["16:20", "t.pryce", "FileAccessed", "198.51.100.12"],
              ["21:47", "d.marsh.home@mailbox.example", "FileDownloaded", "203.0.113.58"],
            ],
            answer: 2,
            why: "Downloaded that evening by the invited address, from outside the office range. Now you have a chain from a warning to a copy off the premises.",
            learned: "The personal address downloaded the bid at 21:47 from 203.0.113.58",
          },
          {
            id: "hr",
            ask: "This is a person, not a host. Find the context a log can't give you.",
            source: "HR case notes (restricted)",
            columns: ["Employee", "Status", "Note"],
            rows: [
              ["D. Marsh", "Active", "Passed over for bid lead. Contact with a rival noted"],
              ["S. Okoro", "Active", "Promoted in June"],
              ["T. Pryce", "Guest", "Contract runs to March"],
            ],
            answer: 0,
            why: "Logs show what happened. Why it happened sits with HR, and from here the case goes to HR and Legal together, not to a chat with D. Marsh.",
            learned: "HR holds context for D. Marsh. Escalate to HR and Legal",
          },
        ],
      },
    ],
  },
};
