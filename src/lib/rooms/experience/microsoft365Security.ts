import type { RoomExperience } from "./types";

// "Operation Inbox Zero" for the "microsoft-365-security" room.
// Script: docs/campaign/38-microsoft-365-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Fairhaven College (fictional), not the graded tasks' corp.com. Lab data
// differs from the graded tasks: the consent game never ranks Secure Score
// actions (q5); the inbound-mail sheet is about impersonation and spoofing,
// never attachment sandboxing (q2); the audit digest never shows an inbox
// rule (q1, la1, flag1) or MailItemsAccessed (q3), and the consent game shows
// grants only as a bouncer would judge them, never the definition asked in q4.
export const MICROSOFT_365_SECURITY: RoomExperience = {
  roomId: "microsoft-365-security",
  codename: "Operation Inbox Zero",
  theme: "m365",
  handler: { name: "Saoirse Doyle", role: "Microsoft 365 Security Lead, Fairhaven College" },
  briefing: [
    "Fairhaven College. 14,000 students, 2,100 staff, and every lecture, grade and payroll run living in one Microsoft 365 tenant.",
    "In September the bursar's office paid a fake invoice for £86,000. The mail came from inside the tenant, from an account that had been quietly taken over.",
    "Saoirse Doyle runs Microsoft 365 security. She wants analysts who know which Defender product sees what, and who can read the audit log like a confession.",
    "Learn the Defender family and Secure Score, how Defender for Office 365 judges a sender, the audit operations that matter, then work a business email compromise.",
  ],
  mission: "Put each signal on the Defender product that sees it, judge four inbound mails for impersonation and spoofing, search the unified audit log for forwarding, role changes and bulk downloads, then work the graded inbox-rule alert.",
  estimate: "~40 min",
  look: { primary: "#38bdf8", secondary: "#a3e635", warn: "#fb923c" },
  scene: "facilitycampus",
  layout: "facility",
  story: {
    intro: { title: "The Invoice From Inside", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-intro-bd3c0f73.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-intro-42651b6d.jpg" },
    afterStation: {
      mail: { title: "A Hyphen, Not a Dot", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-ch2-1c548926.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-ch2-dae4df0b.jpg" },
      audit: { title: "Three Operations, One Story", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-ch3-20685c50.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-ch3-57fc6a41.jpg" },
      boss: { title: "Close the Tenant", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-finale-2925b247.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/microsoft-365-security/inboxzero-finale-d561c583.jpg" },
    },
  },
  stations: [
    {
      id: "family",
      label: "The Defender Family",
      topic: "MDO, MDE, MDI, MDCA, Entra, Purview, Sentinel · Secure Score · the Defender portal",
      tagline: "Who sees what in the tenant",
      building: "control",
      taskIds: ["m365-sec-r1"],
    },
    {
      id: "mail",
      label: "Guarding the Inbox",
      topic: "Defender for Office 365 plans · Safe Links and Safe Attachments · impersonation and spoof intelligence",
      tagline: "Judge the sender, not the subject line",
      building: "lab",
      taskIds: ["m365-sec-r2", "m365-sec-q2"],
    },
    {
      id: "audit",
      label: "The Audit Trail",
      topic: "Unified audit log · retention · the six operations to watch",
      tagline: "Read the tenant's confession",
      building: "vault",
      taskIds: ["m365-sec-r3", "m365-sec-q1", "m365-sec-q3"],
    },
    {
      id: "rule",
      label: "The Hidden Rule",
      topic: "A forwarding inbox rule, field by field",
      tagline: "Find where the mail is going",
      building: "office",
      taskIds: ["m365-sec-la1", "m365-sec-flag1"],
    },
    {
      id: "boss",
      label: "Close the Tenant",
      topic: "Consent phishing · what to fix first",
      tagline: "Shut the doors that stay open",
      building: "ticket",
      taskIds: ["m365-sec-q4", "m365-sec-q5"],
      boss: true,
    },
  ],
  personas: {
    "m365-sec-q1": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "A finance manager's account is taken, and the first move is an inbox rule. Why?" },
    "m365-sec-q3": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "Did they read thousands of mails? Which operation tells me?" },
    "m365-sec-la1": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "Sentinel caught a forwarding rule to an outside domain. Read it." },
    "m365-sec-q5": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "Secure Score 35 out of 100. What do we fix first?" },
  },
  briefings: {
    // ── Reading 1: the family ──
    "m365-sec-r1": [
      {
        kind: "intercept",
        title: "App Governance Door",
        prompt: "Saoirse has you on the Defender for Cloud Apps app governance queue the morning after term starts. Apps are asking to sit inside the Fairhaven tenant with a token. Revoke the grants that do not belong and keep the ones that do.",
        protect: "the Fairhaven tenant",
        blockLabel: "Revoke grant",
        passLabel: "Keep grant",
        seconds: 11,
        items: [
          { id: "gradesync", text: "Moodle Grade Sync asks for Mail.Read, Files.Read.All and offline_access", sub: "Publisher unverified · created 2 days ago · consented by 1 lecturer", bad: true, why: "Mail and file read with offline_access gives a long-lived token that needs no password. An unverified, two-day-old publisher asking for that is what app governance in Defender for Cloud Apps exists to catch." },
          { id: "teamsrooms", text: "Microsoft Teams Rooms asks for Calendars.Read", sub: "Publisher: Microsoft Corporation (verified) · 14,000 users", bad: false, why: "A verified first-party publisher, one narrow scope, a calendar for room booking. Revoking it would break every meeting room for no gain." },
          { id: "financeclose", text: "Finance Close Tool asks for Files.ReadWrite.All", sub: "Publisher verified · admin consent logged under CHG-4471 · finance vendor", bad: false, why: "The scope is wide and looks scary, but the consent came through the admin workflow, with a change ticket and a verified vendor. Scope alone never decides it: who consented, how, and whether it was planned does." },
          { id: "noteshelper", text: "Lecture Notes Helper asks for Mail.Send and Mail.ReadWrite", sub: "Publisher verified · consented by 3 staff, all in the finance office", bad: true, why: "A verified badge proves the publisher exists, not that the app is needed. A lecture tool being consented by finance staff, with send-as-user rights, does not fit who uses it." },
          { id: "meetingsched", text: "Meeting Scheduler asks for Mail.Read on all mailboxes", sub: "Application permission · granted 02:40 · by a service account", bad: true, why: "Application permissions read every mailbox with no user present. Granted at 02:40 by a service account that never consented before is an Entra audit event to chase, not a convenience." },
          { id: "timetable", text: "Student Timetable asks for User.Read and Calendars.Read", sub: "Delegated · used by 9,800 students · reviewed in app governance last term", bad: false, why: "Delegated, narrow, reviewed, and the user count matches the student body. Healthy apps look boring and have a review date." },
          { id: "pdfsigner", text: "PDF Signer asks for Files.Read.All and Sites.Read.All", sub: "12 users consented in 20 minutes · after a mail wave · redirect host not on contract", bad: true, why: "Twelve consents in twenty minutes right after a mail wave is the shape of a consent phishing run. Normal adoption is slow and scattered." },
          { id: "hrsso", text: "HR Portal sign-in asks for openid, profile and email", sub: "Publisher verified · first sign-in for 40 new starters", bad: false, why: "Those three scopes only identify the user. A burst of first sign-ins in September is onboarding, not abuse." },
          { id: "msupdate", text: "Microsoft Security Update asks for Directory.Read.All and Mail.Read", sub: "Publisher unverified · display name imitates a Microsoft product", bad: true, why: "A display name can say anything. Microsoft first-party apps are not registered by tenants; check the publisher and app ID, not the name." },
          { id: "archive", text: "Fairhaven Archive asks for Mail.Read", sub: "Application permission · registered by IT · admin consent CHG-4390 · owner: IT", bad: false, why: "Application-level mail read is the same permission as the bad Meeting Scheduler, but here it has an owner, a ticket and a purpose. Same scope, different story." },
        ],
        lesson: "Read the consent, not just the scope: who granted it, through which path, at what time and with what ticket. Defender for Cloud Apps app governance surfaces the app, Entra audit shows who consented, and unverified publishers, bursts of consents and off-hours application grants are the tells.",
      },
    ],
    // ── Reading 2: Defender for Office 365 ──
    "m365-sec-r2": [
      {
        kind: "hotspot",
        title: "Find the Fakes",
        prompt: "The bursar's inbox this morning, as Defender for Office 365's Explorer shows it. Tap every message you would not trust. Protected users include the Principal, Dr Helen Ward.",
        artifact: "Explorer · Email · bursar@fairhaven.ac.example · today",
        parts: [
          { id: "estates", text: "Estates Office <estates@fairhaven.ac.example> · Boiler rota for November · SPF pass · DKIM pass · DMARC pass", flag: false, note: "Our own domain, every check passing, from a mailbox that sends this every month.", style: "meta" },
          { id: "typo", text: "Fairhaven Payroll <payroll@fairhaven-ac.example> · Updated bank details for staff salaries · SPF pass · DKIM pass", flag: true, note: "A hyphen where the dot should be. It passes SPF and DKIM because the attacker owns that domain: authentication proves who sent it, not that it's ours.", style: "meta" },
          { id: "principal", text: "Dr Helen Ward <h.ward.principal@outlook.example> · Urgent: approve this transfer today", flag: true, note: "The Principal's name on a consumer mailbox: user impersonation, aimed at the person who moves money.", style: "meta" },
          { id: "vendor", text: "Fairhaven Payroll <payroll@fairhaven.ac.example> via mail.payrollco.example · October payslips · allowed by spoof intelligence", flag: false, note: "The real payroll vendor sending on our behalf, a sender spoof intelligence has learned and allowed.", style: "meta" },
          { id: "helpdesk", text: "IT Helpdesk <helpdesk@fairhaven.ac.example> · Your mailbox is full · SPF fail · DKIM none · DMARC fail", flag: true, note: "Our domain in the From line, sent from a server we never authorised. Every check fails: a spoof.", style: "meta" },
          { id: "attach", text: "Fairhaven Suppliers <accounts@supplier-remit.example> · Remittance advice.docm · Safe Attachments: detonated in a cloud sandbox, verdict malware, quarantined", flag: true, note: "Safe Attachments opens each attachment in a cloud sandbox (detonation) before delivery and judges what it does. The verdict here is malware, so the message was pulled before the bursar could open it. Do not release it.", style: "meta" },
          { id: "attachok", text: "Estates Office <estates@fairhaven.ac.example> · Fire-door survey.pdf · Safe Attachments: detonated in a cloud sandbox, verdict clean, delivered", flag: false, note: "The same sandbox detonation, but nothing malicious happened when the file opened, so it was delivered.", style: "meta" },
        ],
      },
    ],
    // ── Reading 3: the audit log ──
    "m365-sec-r3": [
      {
        kind: "spotdiff",
        title: "Quiet Week, Loud Night",
        prompt: "Saoirse pulled the audit digest for p.okoro in the estates office: Monday's baseline beside last night's. Five lines are an attacker's work. Others changed for dull reasons, so tap only the ones that tell a story.",
        goodTitle: "Monday baseline",
        suspectTitle: "Last night",
        good: [
          "Account: p.okoro@fairhaven.ac.example (Estates Office)",
          "Set-Mailbox ForwardingSmtpAddress: (none)",
          "Mailbox type: UserMailbox, Exchange Online",
          "Role group Exchange Administrator: j.brennan, r.achebe",
          "Role changes by p.okoro in 7 days: 0",
          "FileDownloaded, /sites/Estates-BuildingPlans: 11 in 7 days",
          "Mailbox quota: 50 GB",
          "Sign-in ClientIP: 192.0.2.40 (campus)",
          "Audit retention: 180 days",
          "MFA: registered, Authenticator app",
          "Last password change: 41 days ago",
          "MailItemsAccessed (mailbox reads): 140 in 7 days",
          "New-InboxRule: (none)",
        ],
        suspect: [
          "Account: p.okoro@fairhaven.ac.example (Estates Office)",
          "Set-Mailbox ForwardingSmtpAddress: smtp:estates.archive@mailbox.example",
          "Mailbox type: UserMailbox, Exchange Online",
          "Role group Exchange Administrator: j.brennan, r.achebe, svc-o365admin",
          "Role changes by p.okoro in 7 days: 1",
          "FileDownloaded, /sites/Estates-BuildingPlans: 653 in 7 days",
          "Mailbox quota: 100 GB",
          "Sign-in ClientIP: 192.0.2.40 (campus)",
          "Audit retention: 180 days",
          "MFA: registered, Authenticator app",
          "Last password change: 41 days ago",
          "MailItemsAccessed (mailbox reads): 5,200 in 7 days",
          "New-InboxRule: ForwardTo estates.archive@mailbox.example, DeleteMessage True",
        ],
        diffs: [
          { line: 1, why: "Server-side forwarding set with Set-Mailbox: it lives on the mailbox, so the user never sees it in Outlook rules. A copy usually stays in the mailbox too, so nothing looks missing." },
          { line: 3, why: "A new member in Exchange Administrator. Role changes are one of the operations to watch because they widen what the next step can do." },
          { line: 5, why: "From 11 to 653 downloads in a week. Role, forwarding, then bulk download: the three operations tell one story together." },
          { line: 11, why: "MailItemsAccessed is the audit operation that records mailbox reads. 140 to 5,200 in a week means someone read thousands of messages, which a normal user's week never does." },
          { line: 12, why: "A New-InboxRule that forwards to an outside address and deletes the original is the forward-and-delete pattern of business email compromise: the owner never sees the copy leave or the replies come back." },
        ],
        decoys: [
          { line: 4, why: "The counter moved because p.okoro was the one who added the member, so it is the same event as line 3, not a separate finding." },
          { line: 6, why: "A quota raise from a ticket is routine admin work. It matters only if nothing else is wrong, and here the evidence is elsewhere." },
        ],
        lesson: "Read an audit digest as changes between two states, and group them: a role grant, a forwarding address and a download spike together are an account takeover; a quota bump or a counter ticking is not.",
      },
    ],
  },
};
