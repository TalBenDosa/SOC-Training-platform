import type { RoomExperience } from "./types";

// "Operation Shared Link" for the "sharepoint-teams-monitoring" room.
// Script: docs/campaign/57-sharepoint-teams-monitoring.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Wrenhall Architects (fictional), not the graded tasks' corp.com records and not the readings'
// nexacorp examples.
// Signature mechanic: one campaign read from records. A fake help desk in another tenant works
// through Wrenhall; the learner reads who acted in the Teams audit records, then triages the queue
// the same campaign fills, always from the analyst's seat.
// Clarity pass 2026-11-24 (learner: "I didn't understand what the lab is supposed to teach"; expert
// review docs/LAB-EXPERT-REVIEW.md section 5): every lab carries `teaches` and a `primer`; r1 gained
// a field lab on the tenant map; the victim-seat chat and the "no sign-in means no person" deduce
// were replaced by an actor-fields reader and a queue; the download-alert tune moved to r3 beside
// the behavioural indicators it practises.
// Game mix: hunt + spotdiff + tune, plus field labs reader x2 + queue + trace.
// Lab data differs from the graded tasks: no departing employee and no 847-file download
// (la1), no 203.0.113.60 (f1), no vendor_externalco.com guest (q2), the trace follows a
// Specific people link and not an Anyone link (q1), and the labs never say where to search (q3).

export const SHAREPOINT_TEAMS_MONITORING: RoomExperience = {
  roomId: "sharepoint-teams-monitoring",
  codename: "Operation Shared Link",
  theme: "sharedlink",
  handler: { name: "Annika Bergström", role: "Collaboration Security Lead, Wrenhall Architects" },
  briefing: [
    "Wrenhall Architects. 140 people, three bids live, and every drawing they own sits in Microsoft 365.",
    "Nobody at Wrenhall sends files any more. They share them, and a share has no attachment for a mail filter to look at.",
    "Last Thursday, pages from the stadium bid turned up in a rival's presentation. Annika Bergström doesn't think anybody broke in.",
    "Learn where the data lives, who can reach it, how outsiders reach your people through Teams, and how to read what people do with access they already have.",
  ],
  mission: "Place audit records on the tenant map, find what changed in the sharing settings, interview a user who reported a Teams chat, triage the Teams queue, follow one DLP alert across the logs, count every copy in OfficeActivity, tune a download alert, then close the graded case.",
  estimate: "~60 min",
  look: { primary: "#a78bfa", secondary: "#22d3ee", warn: "#fb923c" },
  scene: "facilitysharepointteamsmonitoring",
  layout: "facility",
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
      topic: "Tenant, sites and OneDrive · how Teams maps onto SharePoint · permissions, sharing links and guests · reading a SharePoint audit record",
      tagline: "Where does it live, and who can reach it?",
      building: "control",
      taskIds: ["spt-teams-r1", "spt-teams-q1"],
    },
    {
      id: "channel",
      label: "The Channel",
      topic: "Four ways an outsider reaches your users · Teams phishing patterns · Teams audit records · triaging a reported chat",
      tagline: "Who are you really talking to?",
      building: "office",
      taskIds: ["spt-teams-r2", "spt-teams-q2"],
    },
    {
      id: "override",
      label: "The Override",
      topic: "Purview DLP policies and records · DlpRuleMatch, DlpRuleUndo and DlpInfo · insider risk · bulk-download indicators and the investigation workflow",
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
    // ── Reading 1: the map, then the settings ──
    "spt-teams-r1": [
      {
        kind: "reader",
        title: "Place Each Record on the Map",
        teaches: "Placing SharePoint and OneDrive audit records on the tenant map: team site, channel site, communication site or someone's OneDrive. It practises the reading's site types, the Teams storage map and the URL anatomy. On the job this is the first step of scoping any leak, because the SiteUrl tells you whose membership to pull.",
        primer: {
          title: "Read a path in four moves",
          points: [
            "Host first. tenant.sharepoint.com is a shared site. tenant-my.sharepoint.com/personal/ is one person's OneDrive.",
            "Then the site name. /sites/Team is a team or communication site. /sites/Team-Channel is a private or shared channel's own site, with its own members.",
            "Then the folder. Microsoft Teams Chat Files means the file was sent in a chat. A folder named after a channel means a standard channel.",
            "Then the person. A name with #EXT# is a guest. An AnonymousLinkUsed record has no person behind it.",
          ],
          example: {
            label: "Worked example (a different tenant)",
            lines: [
              "OneDrive, https://nexacorp-my.sharepoint.com/personal/r_haddad_nexacorp_com/, Documents/Microsoft Teams Chat Files, Q3_Forecast.xlsx",
              "Host with -my: a OneDrive. /personal/r_haddad_nexacorp_com: it belongs to r.haddad@nexacorp.com.",
              "Folder Microsoft Teams Chat Files: r.haddad sent this file in a Teams chat.",
              "So the reach is the people in that chat, plus any link r.haddad made. No team site is involved.",
            ],
          },
        },
        prompt: "Annika ran one audit search on the stadium bid and expanded the AuditData column into a sheet. Before anyone argues about who leaked what, place each record on the tenant map: which container, and who could reach it.",
        source: "Audit search export, AuditData expanded · wrenhall tenant · 12 Nov 2026 (UTC)",
        header: ["CreationTime,UserId,Operation,Workload,SiteUrl,SourceRelativeUrl,SourceFileName,ClientIP"],
        lines: [
          "2026-11-12T08:52:10,a.bergstrom@wrenhall.com,FileAccessed,SharePoint,https://wrenhall.sharepoint.com/sites/Intranet/,Shared Documents/Policies,Bid_Confidentiality_Policy.pdf,198.51.100.12",
          "2026-11-12T09:14:02,s.okoro@wrenhall.com,FileModified,SharePoint,https://wrenhall.sharepoint.com/sites/StadiumBid/,Shared Documents/Design,Stadium_Massing_v7.dwg,198.51.100.12",
          "2026-11-12T09:31:47,s.okoro@wrenhall.com,FileUploaded,OneDrive,https://wrenhall-my.sharepoint.com/personal/s_okoro_wrenhall_com/,Documents/Microsoft Teams Chat Files,Facade_Options.pdf,198.51.100.12",
          "2026-11-12T10:05:33,l.ferreira@wrenhall.com,FileDownloaded,SharePoint,https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/,Shared Documents,Cost_Plan_R4.xlsx,198.51.100.12",
          "2026-11-12T10:07:19,l.ferreira@wrenhall.com,AnonymousLinkCreated,SharePoint,https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/,Shared Documents,Cost_Plan_R4.xlsx,198.51.100.12",
          "2026-11-12T11:42:08,t.pryce_partnereng.example#EXT#@wrenhall.onmicrosoft.com,FileAccessed,OneDrive,https://wrenhall-my.sharepoint.com/personal/s_okoro_wrenhall_com/,Documents/Microsoft Teams Chat Files,Facade_Options.pdf,203.0.113.140",
          "2026-11-12T19:26:51,anonymous,AnonymousLinkUsed,SharePoint,https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/,Shared Documents,Cost_Plan_R4.xlsx,203.0.113.77",
          "2026-11-12T20:02:15,m.lindqvist@wrenhall.com,FileSyncDownloadedFull,OneDrive,https://wrenhall-my.sharepoint.com/personal/m_lindqvist_wrenhall_com/,Documents,Site_Photos_Nov.zip,198.51.100.40",
        ],
        notes: {
          0: "/sites/Intranet on the shared host: a communication site that every employee reads. A policy document there is meant to be widely seen.",
          1: "/sites/StadiumBid: the Stadium Bid team's own site. Shared Documents/Design is the folder behind the Design standard channel, so every team member can reach it.",
          4: "Same channel site, under two minutes after the download: an Anyone link was made for the cost plan. From here its reach is anyone who holds the URL.",
          7: "m.lindqvist syncing a folder from her own OneDrive with the sync app. Her personal storage, her own files.",
        },
        objectives: [
          { id: "chat", type: "line", answer: [2, 5], task: "Tap a record about a file that someone sent in a Teams chat.", hint: "Look for the folder Teams creates in the sender's OneDrive.", why: "Files sent in a 1:1 or group chat go to the sender's OneDrive, under Microsoft Teams Chat Files, shared with that chat. Searching the Stadium Bid team site would never find Facade_Options.pdf." },
          { id: "channel", type: "line", answer: [3, 4, 6], task: "Tap a record from a site that only part of the Stadium Bid team can open.", hint: "Compare the site names. One is the team name plus something.", why: "/sites/StadiumBid-CostPlan is the team name, a hyphen and a channel name: the own site of a private or shared channel. Its reach is that channel's members, not the whole team." },
          { id: "guest", type: "value", answer: ["partnereng.example"], task: "Type the home domain of the outside person who opened the chat file.", hint: "A guest's sign-in name is their own address with @ turned into _, then #EXT#.", why: "t.pryce_partnereng.example#EXT# is a guest whose real address is t.pryce@partnereng.example. Guests reach files exactly as employees do, here because s.okoro shared the chat file with the chat." },
          { id: "onedrive", type: "count", answer: 3, match: "wrenhall-my\\.sharepoint\\.com", task: "How many of these records come from personal OneDrive sites?", hint: "Count the host names with -my in them.", why: "Three records sit on wrenhall-my.sharepoint.com, and each also says Workload OneDrive. Two are one person's chat file, one is another person's own sync." },
          { id: "anon", type: "line", answer: [6], task: "Tap the record that no further search can tie to a named person.", hint: "Which operation needs no sign-in at all?", why: "AnonymousLinkUsed: an Anyone link opened without signing in. You get the IP and the time, and the UserId is anonymous. That is why the link's creator, l.ferreira, becomes the person you talk to." },
          { id: "scope", type: "value", answer: ["https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "wrenhall.sharepoint.com/sites/StadiumBid-CostPlan"], task: "Before the Anyone link existed, whose membership limited who could reach Cost_Plan_R4.xlsx? Type that site's SiteUrl.", hint: "The container comes before the links.", why: "The container sets the starting reach: the CostPlan channel site's members. The Anyone link at 10:07 then widened it to anyone with the URL. Scope is always site membership plus every link on the file." },
        ],
        lesson: "Read every path from the outside in: -my means someone's OneDrive, /sites/Team-Channel means a channel's own site, Microsoft Teams Chat Files means a chat. The container gives you the starting reach, and the sharing records tell you how far it grew.",
        fieldNote: "In Microsoft Purview, Audit, export the search and expand AuditData, or query OfficeActivity in Microsoft Sentinel. Group by SiteUrl first, then pull the membership of each site that appears.",
      },
      {
        kind: "spotdiff",
        title: "What Changed in Sharing?",
        teaches: "Spotting which tenant sharing settings widen who can reach a file. It practises the reading's layering rule and the four sharing levels. On the job you compare today's Get-SPOTenant output with the last approved copy after a leak, an audit finding or a SharingPolicyChanged record.",
        primer: {
          title: "What each setting controls",
          points: [
            "SharingCapability is the tenant ceiling. From tightest to widest: Disabled, ExistingExternalUserSharingOnly, ExternalUserSharingOnly, ExternalUserAndGuestSharing (Anyone).",
            "DefaultSharingLinkType is the link the dialog offers first: Direct (specific people), Internal (your organisation) or AnonymousAccess (Anyone). Most people keep the default.",
            "RequireAnonymousLinksExpireInDays caps how long an Anyone link lives, and 0 removes the cap. ExternalUserExpireInDays removes guests after that many days, but only while ExternalUserExpirationRequired is True.",
            "Storage, branding and notification settings do not change who can reach a file.",
          ],
          example: {
            label: "Worked example (a different tenant)",
            lines: [
              "Before: OneDriveSharingCapability : ExistingExternalUserSharingOnly",
              "After:  OneDriveSharingCapability : ExternalUserSharingOnly",
              "Wider: OneDrive owners can now invite brand-new outsiders, not only guests already in the directory.",
              "Next: the SharingPolicyChanged record shows who changed it and when, in ModifiedProperties.",
            ],
          },
        },
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
          { line: 0, why: "This is the ceiling. ExternalUserAndGuestSharing is the Anyone level, the most open setting a tenant has, and it allows links that need no sign-in." },
          { line: 1, why: "The default link is now the widest one. People take the default, so every careless share goes as far as it can." },
          { line: 3, why: "Zero removes the expiry cap, so a link that used to die in a week now lives until someone remembers it." },
          { line: 4, why: "Guest access no longer has to end, so a partner on last year's job can keep theirs." },
        ],
        decoys: [
          { line: 6, why: "More storage, bought with the new licences. It changes nothing about who can reach a file." },
        ],
        lesson: "Attackers and tired admins both change the same few settings. Keep a known-good copy to compare. Each change is also in the audit log as SharingPolicyChanged, with the setting and its old and new values in ModifiedProperties: find who made it and when, then read that admin's sign-in.",
      },
    ],
    // ── Reading 2: the interview, then the queue ──
    "spt-teams-r2": [
      {
        kind: "reader",
        title: "Who Acted in Teams?",
        teaches: "Naming who acted in Teams audit records from the records' own fields: a member, a guest, an external access contact or an app. It practises the reading's actor table and the four ways an outsider gets in. On the job this is how you scope a Teams phishing campaign, and how you notice an app quietly reading channels.",
        primer: {
          title: "Read the actor, never guess it",
          points: [
            "UserId first. Your own domain is a member. A name with #EXT# is a guest with an account in your tenant. A UPN in another tenant's domain, often name.onmicrosoft.com, is an external access contact.",
            "UserType next. 0 is a regular user. 5 is an application and 6 a service principal: software acted, and AppAccessContext.ClientAppName names it.",
            "Then the operation. ChatCreated and UserAccepted are chats; MemberAdded is someone joining a team; MessagesListed exists only when a Graph app reads messages.",
            "Never conclude by elimination. A stolen token acts with no new sign-in, so the record's own fields are the evidence.",
          ],
          example: {
            label: "Worked example (a different tenant)",
            lines: [
              "2026-10-02T14:05:11 | MessagesListed | 7d2e9a40-1c6b-4e55-8f3d-2b9c0e71a6d4 | 5 | Agenda Helper | TeamName: Payroll",
              "UserType 5 and a GUID as UserId: an application read the Payroll team's messages, not a person.",
              "ClientAppName: the app is Agenda Helper. MessagesListed is only written for Graph calls.",
              "Next: find AppInstalled for Agenda Helper, and Consent to application in the Entra audit log, to learn who let it in.",
            ],
          },
        },
        prompt: "Three Wrenhall staff reported chats from \"IT Help Desk\" this week. Annika pulled every Teams record from that morning onward. Read who acted in each one, scope the campaign, and find anything else in the team that is acting on its own.",
        source: "Unified Audit Log · Workload MicrosoftTeams · wrenhall tenant · 13 Nov 2026 (UTC)",
        header: ["CreationTime | Operation | UserId | UserType | AppAccessContext.ClientAppName | Other fields"],
        lines: [
          "2026-11-13T08:40:12 | ChatCreated | help@wrenhall-support.onmicrosoft.com | 0 |  | Members: help@wrenhall-support.onmicrosoft.com, r.bello@wrenhall.com",
          "2026-11-13T08:43:55 | ChatCreated | help@wrenhall-support.onmicrosoft.com | 0 |  | Members: help@wrenhall-support.onmicrosoft.com, m.lindqvist@wrenhall.com",
          "2026-11-13T08:46:20 | ChatCreated | help@wrenhall-support.onmicrosoft.com | 0 |  | Members: help@wrenhall-support.onmicrosoft.com, d.marsh@wrenhall.com",
          "2026-11-13T08:47:31 | UserAccepted | m.lindqvist@wrenhall.com | 0 |  | Accepted a message from help@wrenhall-support.onmicrosoft.com",
          "2026-11-13T08:48:02 | MessageSent | m.lindqvist@wrenhall.com | 0 |  | Chat with help@wrenhall-support.onmicrosoft.com",
          "2026-11-13T09:15:40 | MemberAdded | a.bergstrom@wrenhall.com | 0 |  | TeamName: Stadium Bid; Members.UPN: j.adeyemi_structura.example#EXT#@wrenhall.onmicrosoft.com",
          "2026-11-13T10:02:17 | AppInstalled | s.okoro@wrenhall.com | 0 |  | TeamName: Stadium Bid; AddOnName: Drawing Converter",
          "2026-11-13T23:41:05 | MessagesListed | 4b7e2c91-5d3a-4f08-9e6b-a1c0d27f8e43 | 5 | Drawing Converter | TeamName: Stadium Bid; ChannelName: Design",
          "2026-11-13T23:41:09 | MessageHostedContentsListed | 4b7e2c91-5d3a-4f08-9e6b-a1c0d27f8e43 | 5 | Drawing Converter | TeamName: Stadium Bid; ChannelName: Design",
        ],
        notes: {
          0: "An external access chat: the sender's UPN is in another tenant's onmicrosoft.com domain. UserType 0 only says a regular user; the domain says whose.",
          1: "The same external sender opening a second chat, this time with m.lindqvist.",
          2: "A third chat from the same sender, with d.marsh. d.marsh never accepted, so no further record follows.",
          4: "m.lindqvist replying. MessageSent is written here only because the chat has an external participant; chats between two employees leave none.",
        },
        objectives: [
          { id: "sender", type: "value", answer: ["wrenhall-support.onmicrosoft.com"], task: "Type the domain the \"IT Help Desk\" really writes from.", hint: "Read UserId on the ChatCreated records, not the display name.", why: "wrenhall-support.onmicrosoft.com is another tenant's initial domain. The sender reached staff by external access: there is no account for it in Wrenhall's Entra ID, and it can never open Wrenhall's files directly." },
          { id: "reach", type: "count", answer: 3, match: "\\| ChatCreated \\| help@wrenhall-support", task: "How many Wrenhall staff did that sender open a chat with?", hint: "Count the ChatCreated records from that sender.", why: "Three chats in six minutes: r.bello, m.lindqvist and d.marsh. Only one person reported it, so every name on this list needs a check, not just the reporter." },
          { id: "accepted", type: "line", answer: [3], task: "Tap the record that shows a user let the sender in.", hint: "Which operation is written when someone accepts a message request?", why: "UserAccepted: m.lindqvist accepted the stranger's request at 08:47. From here you check her device's process events for quickassist.exe and her sign-in logs, interactive and non-interactive." },
          { id: "guest", type: "line", answer: [5], task: "Tap the record where an outsider received a real account's access to a team.", hint: "Look for #EXT# in the record.", why: "MemberAdded with a #EXT# UPN: a guest joined Stadium Bid and can now open its channels and team site. That is guest access, a different door from the external chats above, with far more reach." },
          { id: "app", type: "line", answer: [7, 8], task: "Tap a record where software, not a person, acted.", hint: "Read UserType and AppAccessContext.ClientAppName.", why: "UserType 5 with a GUID as UserId and Drawing Converter as the client app: an application read the Design channel's messages at 23:41. MessagesListed is only written for Graph calls, so this is an app pulling messages in bulk." },
          { id: "origin", type: "line", answer: [6], task: "Tap the record that shows how that app got into the team.", hint: "Find the same app's name in an earlier record.", why: "AppInstalled by s.okoro at 10:02 put Drawing Converter into Stadium Bid. Next, find Consent to application in the Entra audit log to see what permissions it holds, then remove the app and revoke its consent." },
        ],
        lesson: "Name the actor from the record: the UserId's domain, #EXT#, UserType and the client app. An external access contact can only chat, a guest can open the team's files, and an app keeps whatever it was granted until someone removes it.",
        fieldNote: "In Microsoft Sentinel these records are in OfficeActivity; in Defender XDR advanced hunting, Teams activity from Defender for Cloud Apps is in CloudAppEvents. App consents are in the Entra audit log under Consent to application.",
      },
      {
        kind: "queue",
        title: "Triage the Teams Queue",
        teaches: "Triaging Teams and SharePoint alerts by the door the outsider used: external access, a guest account, or someone inside. It practises the reading's four paths, the audit records each one leaves, and when to contain or escalate. On the job this is the daily Microsoft 365 queue in your SIEM.",
        primer: {
          title: "Three questions for every Teams alert",
          points: [
            "Which door? An onmicrosoft.com sender from another tenant is external access. A #EXT# name is a guest. A plain company name is one of your own people.",
            "Is it expected? An owner adding a named partner, or a member linking to the team's own files, is normal work. Verify with the owner when the context points to one.",
            "Is it still happening? Live and spreading: contain first. Already over, with data moved: escalate so someone scopes it.",
          ],
          example: {
            label: "Worked example (different data)",
            lines: [
              "Alert: MemberAdded on team Payroll, Members.UPN r.ito_lumenarch.example#EXT#@nexacorp.onmicrosoft.com, added at 23:10.",
              "Door: a guest. The team owner who added it signed in from an unfamiliar country ten minutes earlier.",
              "Expected? No partner contract names Lumen Arch, and payroll teams rarely have guests.",
              "Call: escalate as a possible owner-account compromise, and confirm with the owner by phone before removing the guest.",
            ],
          },
        },
        prompt: "The same week, four Microsoft 365 alerts are waiting at Wrenhall. Read each one's fields and context, use Verify with IT where an owner is named, and take the action an analyst would.",
        console: "SIEM · Microsoft 365 alerts",
        actions: [
          { id: "close", label: "Close as expected", tone: "close" },
          { id: "escalate", label: "Escalate to incident", tone: "escalate" },
          { id: "contain", label: "Contain now (block sender or account)", tone: "contain" },
        ],
        alerts: [
          {
            id: "tq1", time: "2026-11-13 08:58", severity: "High", rule: "Teams: external sender flagged for impersonation", entity: "help@wrenhall-support.onmicrosoft.com",
            fields: [{ k: "Operation", v: "TeamsImpersonationDetected" }, { k: "Workload", v: "MicrosoftTeams" }, { k: "ChatCreated to Wrenhall users, 08:40 to 08:46", v: "3" }, { k: "UserAccepted", v: "m.lindqvist@wrenhall.com, 08:47" }],
            context: "Wrenhall's IT desk works only through the internal ticket portal and never starts chats from another tenant. EDR shows quickassist.exe starting on Lindqvist's laptop at 08:49 and closing at 08:55. External access is still at the default: all external domains allowed.",
            answer: "contain",
            why: "One sender in another tenant, three staff in six minutes, one acceptance followed by Quick Assist, and the domain is still allowed. The campaign is live, so contain first: block the domain in Teams external access so nobody else accepts. Then open the incident, check what ran on Lindqvist's laptop between 08:49 and 08:55, and read her sign-in logs, interactive and non-interactive.",
          },
          {
            id: "tq2", time: "2026-11-13 10:12", severity: "Low", rule: "Teams: guest added to a team", entity: "Stadium Bid (team)",
            fields: [{ k: "Operation", v: "MemberAdded" }, { k: "UserId", v: "a.bergstrom@wrenhall.com" }, { k: "TeamName", v: "Stadium Bid" }, { k: "Members.UPN", v: "j.adeyemi_structura.example#EXT#@wrenhall.onmicrosoft.com" }],
            context: "A. Bergström owns the Stadium Bid team. Structura Engineering is the structural partner named in the bid contract, and the kick-off meeting with them ended at 10:00.",
            verify: { result: "confirmed", message: "Annika Bergström: yes, J. Adeyemi is Structura's lead engineer on the stadium bid. I added him after kick-off. He is in the partner register, with an end date in March." },
            answer: "close",
            why: "A team owner added a named partner's engineer right after kick-off, and the owner confirms it. Close it as expected. Note the end date: a guest who outlives the project is how the next alert in this queue happens.",
          },
          {
            id: "tq3", time: "2026-11-14 07:40", severity: "High", rule: "SharePoint: mass download by a guest", entity: "k.osei_northbeam.example#EXT#@wrenhall.onmicrosoft.com",
            fields: [{ k: "Operation", v: "FileDownloaded" }, { k: "SiteUrl", v: "https://wrenhall.sharepoint.com/sites/HarbourBid/" }, { k: "Records, 01:52 to 02:14", v: "318" }, { k: "ClientIP", v: "203.0.113.201" }, { k: "Guest access to the site", v: "Removed 03:00 by guest expiration" }],
            context: "Northbeam was Wrenhall's partner on the Harbour bid, which closed in September. Nobody removed the guest from the team. Guest expiration then removed the account's site access at 03:00, after the downloads.",
            answer: "escalate",
            why: "The access is already gone, so there is nothing left to contain. But 318 files left a closed bid's site through a guest nobody removed. Escalate: scope exactly what was taken, involve the partner, and review every guest on finished projects.",
          },
          {
            id: "tq4", time: "2026-11-14 11:20", severity: "Low", rule: "Teams: message with a link posted in a channel", entity: "s.okoro@wrenhall.com",
            fields: [{ k: "Operation", v: "MessageCreatedHasLink" }, { k: "TeamName", v: "Stadium Bid" }, { k: "ChannelName", v: "Design" }, { k: "MessageURLs", v: "https://wrenhall.sharepoint.com/sites/StadiumBid/Shared%20Documents/Design/Stadium_Massing_v8.dwg" }],
            context: "S. Okoro is a Stadium Bid member. Her sign-ins this week came from the office and from her managed laptop.",
            answer: "close",
            why: "A member posted a link to a file in her own team's Design folder. The URL points inside Wrenhall's tenant, to a site every team member can already open. Close it, and tune the rule to links that leave your own domains.",
          },
        ],
        fieldNote: "These are Unified Audit Log records with Workload MicrosoftTeams or SharePoint, as your SIEM indexes them; in Microsoft Sentinel they sit in OfficeActivity. Blocking a domain is done in the Teams admin center under External access.",
      },
    ],
    // ── Reading 3: following a DLP alert, counting every copy, then tuning the download alert ──
    "spt-teams-r3": [
      {
        kind: "trace",
        title: "Follow the Override",
        teaches: "Following one DLP alert across the audit log to a decision: the match, the override, the share and the outside access. It practises the reading's DlpRuleMatch and DlpRuleUndo records, the sharing records and the hand-off to HR. On the job this is how a low alert left in the queue becomes an insider case.",
        primer: {
          title: "The four hops of a DLP case",
          points: [
            "Match: open the DlpRuleMatch with the highest count and confidence, not the first one in the queue.",
            "Decision: a DlpRuleUndo with Reason Override carries the user's own justification. Your job is to test whether it is true.",
            "Movement: the sharing records on the same file. SecureLinkCreated plus AddedToSecureLink names the recipient; AnonymousLinkCreated names nobody.",
            "Use: an access by that recipient from outside. Then context from HR, asked through HR.",
          ],
          example: {
            label: "Worked example (a benign ending)",
            lines: [
              "DlpRuleMatch: policy Payroll data, IBAN x212, High, r.haddad, Bonus_2026.xlsx",
              "DlpRuleUndo: Reason Override, Justification \"external auditor needs it\"",
              "AddedToSecureLink: Bonus_2026.xlsx, TargetUserOrGroupName audit@ledgerline.example",
              "Finance confirms Ledgerline is the appointed auditor. The justification is true, so the case closes with a note.",
            ],
          },
        },
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
            why: "63 high-confidence matches in one file. One match is a person quoting a reference; 63 is the document itself.",
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
              ["14:39", "DlpRuleUndo", "Stadium_Bid_v9.pdf", "Reason: Override. Justification: client asked for it"],
            ],
            answer: 2,
            why: "DlpRuleUndo with Reason Override means a person read the warning and chose to go past it, with a reason in their own words. It's a decision on record. The next question is whether the reason is true.",
            learned: "d.marsh overrode the policy tip at 14:39: \"client asked for it\"",
          },
          {
            id: "share",
            ask: "If a client really asked, there's a share to a client. Find who the file was shared with.",
            source: "Audit · Stadium_Bid_v9.pdf · sharing",
            columns: ["Time", "User", "Operation", "TargetUserOrGroupName"],
            rows: [
              ["14:41", "d.marsh", "SecureLinkCreated", ""],
              ["14:41", "d.marsh", "AddedToSecureLink", "d.marsh.home@mailbox.example"],
              ["16:20", "t.pryce", "FileAccessed", ""],
            ],
            answer: 1,
            why: "SecureLinkCreated makes a Specific people link, and AddedToSecureLink names who it works for. That's no client: a personal address with the same person's name, two minutes after the override.",
            learned: "d.marsh made a Specific people link for a personal address at 14:41",
          },
          {
            id: "open",
            ask: "Was the link used? Find the first access from outside.",
            source: "Audit · Stadium_Bid_v9.pdf · from 14:41",
            columns: ["Time", "User", "Operation", "ClientIP"],
            rows: [
              ["15:30", "s.okoro@wrenhall.com", "FileModified", "198.51.100.12"],
              ["21:47", "d.marsh.home_mailbox.example#EXT#@wrenhall.onmicrosoft.com", "FileAccessed", "203.0.113.58"],
              ["21:48", "d.marsh.home_mailbox.example#EXT#@wrenhall.onmicrosoft.com", "FileDownloaded", "203.0.113.58"],
            ],
            answer: 1,
            why: "Redeeming the link made a guest account for the personal address, so it now appears with #EXT#. It opened the bid that evening from outside the office range, then downloaded it a minute later. You have a chain from a warning to a copy off the premises.",
            learned: "The personal address opened the bid at 21:47 and downloaded it at 21:48, from 203.0.113.58",
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
      {
        kind: "hunt",
        title: "Count Every Copy in OfficeActivity",
        teaches: "Querying the audit log for every route a file copy can take, not only browser downloads. It practises the reading's point that sync and copy count as copies, and its OfficeActivity query. On the job you run this in Microsoft Sentinel when a site's data turns up outside and you must list who took files from it.",
        primer: {
          title: "OfficeActivity in four lines",
          points: [
            "OfficeActivity is Microsoft Sentinel's table of Unified Audit Log records. SharePoint's SiteUrl is called Site_Url there.",
            "Each line filters what the line above returned. has finds text inside a value; in keeps rows whose value is in a list.",
            "A copy can be FileDownloaded (browser), FileSyncDownloadedFull (sync app) or FileCopied. Filtering on one of them misses the others.",
            "summarize count() by UserId turns the remaining rows into one row per person.",
          ],
          example: {
            label: "A short hunt on another site",
            lines: [
              "OfficeActivity",
              "| where Site_Url has \"Payroll\"",
              "| where Operation in (\"FileDownloaded\", \"FileSyncDownloadedFull\", \"FileCopied\")",
              "| summarize count() by UserId",
              "One row per person who copied anything off the Payroll site, by any route.",
            ],
          },
        },
        prompt: "Pages of Cost_Plan_R5.xlsx were quoted back to Wrenhall by a rival. Annika needs the list of everyone who took a copy of anything from the cost-plan channel's site on Monday, by any route. Build the query one line at a time.",
        language: "KQL",
        console: "Logs",
        start: "OfficeActivity",
        goal: "one row per person who copied files off the cost-plan site",
        tables: [
          {
            name: "OfficeActivity",
            note: "Unified Audit Log records for SharePoint and OneDrive, Monday 16 Nov 2026 (UTC).",
            columns: ["TimeGenerated", "UserId", "Operation", "Site_Url", "SourceFileName", "ClientIP"],
            rows: [
              ["2026-11-16 09:10", "l.ferreira@wrenhall.com", "FileAccessed", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Cost_Plan_R5.xlsx", "198.51.100.12"],
              ["2026-11-16 09:12", "l.ferreira@wrenhall.com", "FileDownloaded", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Cost_Plan_R5.xlsx", "198.51.100.12"],
              ["2026-11-16 10:30", "s.okoro@wrenhall.com", "FileModified", "https://wrenhall.sharepoint.com/sites/StadiumBid/", "Stadium_Massing_v8.dwg", "198.51.100.12"],
              ["2026-11-16 11:05", "r.bello@wrenhall.com", "FileSyncDownloadedFull", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Rates_Library.xlsx", "198.51.100.40"],
              ["2026-11-16 11:05", "r.bello@wrenhall.com", "FileSyncDownloadedFull", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Cost_Plan_R5.xlsx", "198.51.100.40"],
              ["2026-11-16 13:22", "a.bergstrom@wrenhall.com", "FileDownloaded", "https://wrenhall.sharepoint.com/sites/StadiumBid/", "Programme_v13.xlsx", "198.51.100.12"],
              ["2026-11-16 14:48", "d.marsh@wrenhall.com", "FileCopied", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Cost_Plan_R5.xlsx", "198.51.100.12"],
              ["2026-11-16 15:02", "m.lindqvist@wrenhall.com", "FileAccessed", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Cost_Plan_R5.xlsx", "198.51.100.12"],
              ["2026-11-16 19:40", "l.ferreira@wrenhall.com", "FileDownloaded", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Subcontractor_Quotes.pdf", "203.0.113.91"],
              ["2026-11-16 20:15", "s.okoro@wrenhall.com", "FileSyncDownloadedFull", "https://wrenhall.sharepoint.com/sites/StadiumBid/", "Facade_Details.pdf", "198.51.100.12"],
              ["2026-11-16 21:03", "anonymous", "AnonymousLinkUsed", "https://wrenhall.sharepoint.com/sites/StadiumBid-CostPlan/", "Cost_Plan_R4.xlsx", "203.0.113.77"],
            ],
          },
        ],
        rungs: [
          {
            id: "site", ask: "Line 2: keep only the cost-plan channel's site.",
            choices: [
              { id: "a", text: '| where Site_Url has "StadiumBid"', why: "Every Stadium Bid site matches that, so the main team site's rows come along too. The channel site is a separate site with its own name.", apply: { op: "where", col: "Site_Url", test: "has", value: "StadiumBid" } },
              { id: "b", text: '| where Site_Url has "StadiumBid-CostPlan"', right: true, why: "The team name plus the channel name: the private channel's own site. Eight rows, and only that site.", apply: { op: "where", col: "Site_Url", test: "has", value: "StadiumBid-CostPlan" } },
              { id: "c", text: '| where SourceFileName has "Cost_Plan"', why: "That follows a file name, not the container. It drops the other files on the site, and Annika asked for anything taken from it.", apply: { op: "where", col: "SourceFileName", test: "has", value: "Cost_Plan" } },
            ],
          },
          {
            id: "copies", ask: "Line 3: keep every operation that puts a copy somewhere else.",
            choices: [
              { id: "a", text: '| where Operation == "FileDownloaded"', why: "Two rows, and both are l.ferreira. r.bello's sync and d.marsh's copy are gone, the exact blind spot the reading warned about.", apply: { op: "where", col: "Operation", test: "eq", value: "FileDownloaded" } },
              { id: "b", text: '| where Operation in ("FileAccessed", "AnonymousLinkUsed")', why: "Those are reads and a link use, not copies made by your people. Opening a file in the browser leaves no copy behind.", apply: { op: "where", col: "Operation", test: "in", value: ["FileAccessed", "AnonymousLinkUsed"] } },
              { id: "c", text: '| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileCopied")', right: true, why: "Browser downloads, sync-app downloads and copies inside SharePoint: five rows, from three people.", apply: { op: "where", col: "Operation", test: "in", value: ["FileDownloaded", "FileSyncDownloadedFull", "FileCopied"] } },
            ],
          },
          {
            id: "who", ask: "Line 4: turn the rows into one line per person.",
            choices: [
              { id: "a", text: "| summarize count() by UserId", right: true, why: "Three people: l.ferreira and r.bello with two copies each, d.marsh with one. That is Annika's list.", apply: { op: "summarize", by: ["UserId"], as: "count_" } },
              { id: "b", text: "| summarize count() by ClientIP", why: "That groups by address. The office egress 198.51.100.12 hides two different people behind one row.", apply: { op: "summarize", by: ["ClientIP"], as: "count_" } },
              { id: "c", text: "| project UserId, SourceFileName", why: "Still one row per copy, five rows with repeats, not one per person.", apply: { op: "project", cols: ["UserId", "SourceFileName"] } },
            ],
          },
        ],
        expect: 3,
        lesson: "Filter on the container, then on every copy operation, then count by person. FileDownloaded alone would have named one person and missed the sync and the copy. Next, take each name to the endpoint: where did those files go after the laptop?",
        fieldNote: "This is the same query you run in Microsoft Sentinel's Logs against OfficeActivity, or in Purview Audit search with the three operations selected. Add the TimeGenerated window of the case.",
      },
      {
        kind: "tune",
        title: "Tune the Download Alert",
        teaches: "Writing a bulk-download alert that catches theft without paging on honest work. It practises the reading's behavioural indicators: volume measured against normal work, and access to places a person never used. On the job you tune rules like this in your SIEM or in Defender for Cloud Apps after the first week of false positives.",
        primer: {
          title: "Two signals beat one",
          points: [
            "Volume alone: an archivist moving a finished project looks exactly like a thief.",
            "Novelty alone: a new starter reading the standards library looks like reconnaissance.",
            "Both together, measured against the person's own last 30 days and their peers, separate a slow, wide-ranging thief from honest bulk work.",
            "Defender for Cloud Apps' Mass download by a single user template starts at more than 50 downloads in one minute. Treat a default like that as a starting point to tune.",
          ],
          example: {
            label: "Worked example (different data)",
            lines: [
              "Rule: files in one session at least 200 AND new folders at least 5",
              "Records clerk, 450 files, 1 new folder: quiet. Volume yes, novelty no.",
              "Intern, 60 files, 9 new folders: quiet. Novelty yes, volume no.",
              "Night session, 380 files, 11 new folders: alert. Both signals at once.",
            ],
          },
        },
        prompt: "Wrenhall's bulk-download alert fires on everything, so nobody reads it. Annika gives you last quarter's seven worst days. Set the two dials so it catches the three real thefts and stays quiet on honest work.",
        eventColumn: "Session",
        dials: [
          { id: "files", label: "Files downloaded in one session, at least", short: "Files", min: 10, max: 500, step: 10, start: 10, dir: "above" },
          { id: "fresh", label: "Folders this person did not open in the previous 30 days, at least", short: "New folders", min: 0, max: 20, step: 1, start: 0, dir: "above" },
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
    ],
  },
};
